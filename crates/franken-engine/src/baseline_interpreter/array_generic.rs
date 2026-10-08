//! Array.prototype methods (ES2020 23.1.3) on a receiver that is not an
//! Array: a Proxy, an array-like object, a primitive `this`; and concat
//! spreading a Proxy or an object with @@isConcatSpreadable.
//!
//! The ordinary paths read an array's element storage directly, and a Proxy
//! has none of its own: `proxy.push(x)` changed nothing, `map` returned `[]`,
//! `indexOf` gave -1 and `Array.isArray(proxy)` was false, so immer's drafts
//! and reactive arrays (Vue, MobX, valtio) misbehaved silently. On an
//! array-like they read data properties only, so a `length` getter or an
//! inherited length counted as 0, element getters read as missing, and a
//! boolean or number `this` was a TypeError. Here the methods run as the
//! specification writes them, over [[Get]], [[Set]], [[HasProperty]] and
//! [[Delete]], so getters and proxy traps observe every step.
//!
//! Callbacks and traps run without a nested collection request, so the
//! arrays and values held here stay reachable while guest code runs.
//!
//! No-claim: on a proxy `values`/`keys`/`entries` (and so for-of) read the
//! elements when the iterator is created, not lazily (an array-like keeps the
//! ordinary lazy iterator); `flat`, `flatMap` and `toSpliced` keep the
//! ordinary paths, as do typed arrays used as array-likes. A function `this`
//! runs here over its own properties (bd-9vouw.285).

use super::*;

use std::cmp::Ordering;

const MAX_SAFE_LENGTH: u64 = (1 << 53) - 1;

impl InterpreterCore {
    /// The Array.prototype methods `array_method_generic` implements.
    pub(super) fn has_generic_array_path(kind: BuiltinFunctionKind) -> bool {
        use BuiltinFunctionKind as K;
        matches!(
            kind,
            K::ArrayPush
                | K::ArrayPop
                | K::ArrayShift
                | K::ArrayUnshift
                | K::ArraySplice
                | K::ArraySliceMethod
                | K::ArrayConcat
                | K::ArrayIndexOf
                | K::ArrayLastIndexOf
                | K::ArrayIncludes
                | K::ArrayJoin
                | K::ArrayToString
                | K::ArrayReverse
                | K::ArrayFill
                | K::ArrayCopyWithin
                | K::ArrayAt
                | K::ArrayForEach
                | K::ArrayMap
                | K::ArrayFilter
                | K::ArraySome
                | K::ArrayEvery
                | K::ArrayFind
                | K::ArrayFindIndex
                | K::ArrayFindLast
                | K::ArrayFindLastIndex
                | K::ArrayReduce
                | K::ArrayReduceRight
                | K::ArraySort
                | K::ArrayToSorted
                | K::ArrayToReversed
                | K::ArrayWith
                | K::ArrayKeys
                | K::ArrayValues
                | K::ArrayEntries
        )
    }

    /// The object the Array.prototype method `kind` runs on generically, or
    /// `None` for the ordinary path: a Proxy; an object that is not an
    /// Array (an arguments object, `{ length: 2, 0: 'a' }`, a String
    /// wrapper), except for the iterator methods, which stay lazy; a
    /// primitive `this`, boxed (ToObject); a function `this`, through the
    /// object holding its own properties (its indices and `length`,
    /// bd-9vouw.285; a callable proxy's record); and an Array receiver of a
    /// concat that must spread generically. Arrays read their element
    /// storage, and typed arrays keep their own paths, except that
    /// Array.prototype.join (not %TypedArray%.prototype.join,
    /// `typed_array_method`) runs on a typed array generically: its length
    /// is read before the separator's ToString, which may resize the
    /// buffer, and an index past the new length reads undefined
    /// (bd-9vouw.256).
    pub(super) fn generic_array_receiver(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        typed_array_method: bool,
        receiver: Option<&Value>,
        args: RegRange,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        use BuiltinFunctionKind as K;
        let iterator = matches!(kind, K::ArrayKeys | K::ArrayValues | K::ArrayEntries);
        match receiver {
            Some(function) if function.is_callable() && !iterator => {
                if let Value::BuiltinFunction(builtin) = function
                    && let Some(object) = Self::builtin_function_property_object(builtin)
                {
                    return Ok(Some(object));
                }
                self.ensure_function_own_property_object(module, function)
            }
            Some(Value::Object(object_id)) => {
                let object_id = *object_id;
                if self.active_proxy_record(object_id)?.is_some() {
                    return Ok(Some(object_id));
                }
                let (is_array, is_typed_array) = self
                    .heap
                    .get(object_id.0 as usize)
                    .map_or((true, false), |object| {
                        (object.is_array, object.typed_array.is_some())
                    });
                if is_array || self.builtin_prototypes.get("Array") == Some(&object_id) {
                    // A length-changing method on an Array whose `length`
                    // is not writable (defineProperty, freeze) runs
                    // generically: its Set(O, "length", len, true) fails with
                    // a TypeError (ES2020 23.1.3.17 and relatives), where the
                    // element-storage path changed the length anyway.
                    let length_locked =
                        matches!(
                            kind,
                            K::ArrayPush
                                | K::ArrayPop
                                | K::ArrayShift
                                | K::ArrayUnshift
                                | K::ArraySplice
                        ) && self.heap.get(object_id.0 as usize).is_some_and(|object| {
                            !object
                                .own_property_attributes(&RuntimePropertyKey::String(
                                    JsString::from("length"),
                                ))
                                .writable
                        });
                    let generic = (kind == K::ArrayConcat
                        && self.concat_spreads_generically(object_id, args)?)
                        || self.converts_object_argument(kind, args)?
                        || length_locked
                        || (kind == K::ArraySort
                            && !self.array_sorts_on_element_storage(object_id, args)?)
                        || (kind == K::ArrayCopyWithin
                            && !self.array_has_dense_data_elements(object_id));
                    return Ok(generic.then_some(object_id));
                }
                let generic_typed_array = kind == K::ArrayJoin && !typed_array_method;
                Ok(((!is_typed_array || generic_typed_array) && !iterator).then_some(object_id))
            }
            Some(
                primitive @ (Value::Bool(_)
                | Value::Int(_)
                | Value::Float(_)
                | Value::Str(_)
                | Value::BigInt(_)
                | Value::Symbol(_)),
            ) if !iterator => Ok(Some(self.alloc_primitive_wrapper(primitive.clone())?)),
            _ => Ok(None),
        }
    }

    /// Whether an Array receiver's method must run generically because an
    /// argument it ToNumbers (an index, a length, a count) or ToStrings
    /// (join's separator) is an object: the element-storage paths convert
    /// primitives only, so `[1, 2, 3].slice({ valueOf() { return 1 } })`
    /// ignored the start. Arguments that are values (indexOf's search
    /// element, fill's value, splice's items) do not count.
    fn converts_object_argument(
        &self,
        kind: BuiltinFunctionKind,
        args: RegRange,
    ) -> Result<bool, InterpreterError> {
        use BuiltinFunctionKind as K;
        let positions: &[u32] = match kind {
            K::ArraySliceMethod | K::ArraySplice => &[0, 1],
            K::ArrayAt | K::ArrayWith | K::ArrayJoin => &[0],
            K::ArrayFill => &[1, 2],
            K::ArrayCopyWithin => &[0, 1, 2],
            K::ArrayIndexOf | K::ArrayLastIndexOf | K::ArrayIncludes => &[1],
            _ => return Ok(false),
        };
        for &position in positions {
            if position < args.count
                && self
                    .builtin_arg(args, position)?
                    .is_some_and(|value| value.is_object_like())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether Array.prototype.sort may sort the Array `array_id`'s element
    /// storage directly: the comparator is undefined or callable, every
    /// index below the length is an own writable data property, and without
    /// a comparator every element is a primitive other than a Symbol, whose
    /// ToString runs no guest code. Otherwise the sort runs generically, as
    /// ES2023 23.1.3.30 writes it: holes are skipped and deleted after the
    /// sorted values, element getters and setters run, an object's ToString
    /// calls its `toString`, and any other comparator is a TypeError.
    fn array_sorts_on_element_storage(
        &self,
        array_id: ObjectId,
        args: RegRange,
    ) -> Result<bool, InterpreterError> {
        let compared = match self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined) {
            Value::Undefined => false,
            comparator if comparator.is_callable() => true,
            _ => return Ok(false),
        };
        let Some(object) = self.heap.get(array_id.0 as usize) else {
            return Ok(false);
        };
        let Some(Value::Int(length)) = object.properties.get("length") else {
            return Ok(false);
        };
        for index in 0..*length {
            let key = RuntimePropertyKey::String(JsString::from(index.to_string()));
            match object.own_runtime_property_value(&key) {
                None | Some(Value::Accessor { .. }) => return Ok(false),
                Some(
                    Value::Undefined
                    | Value::Null
                    | Value::Bool(_)
                    | Value::Int(_)
                    | Value::Float(_)
                    | Value::Str(_)
                    | Value::BigInt(_),
                ) => {}
                Some(_) if compared => {}
                Some(_) => return Ok(false),
            }
            if !object.own_property_attributes(&key).writable {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether every index below the Array `array_id`'s length is an own
    /// writable data property, so copyWithin's element-storage path moves
    /// the same values the spec steps would; a hole (deleted at the target),
    /// an accessor (its getter and setter run) or a read-only element (a
    /// TypeError) takes the generic path (bd-9vouw.276).
    fn array_has_dense_data_elements(&self, array_id: ObjectId) -> bool {
        let Some(object) = self.heap.get(array_id.0 as usize) else {
            return false;
        };
        let Some(Value::Int(length)) = object.properties.get("length") else {
            return false;
        };
        (0..*length).all(|index| {
            let key = RuntimePropertyKey::String(JsString::from(index.to_string()));
            !matches!(
                object.own_runtime_property_value(&key),
                None | Some(Value::Accessor { .. })
            ) && object.own_property_attributes(&key).writable
        })
    }

    /// Whether concat on the Array `receiver` must spread generically: an
    /// argument is a Proxy, or the receiver or an argument has an
    /// @@isConcatSpreadable property. Read without running guest code: a
    /// Proxy on a prototype chain counts as having one.
    fn concat_spreads_generically(
        &self,
        receiver: ObjectId,
        args: RegRange,
    ) -> Result<bool, InterpreterError> {
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::IsConcatSpreadable.id());
        let mut objects = vec![receiver];
        for index in 0..args.count {
            if let Some(Value::Object(object_id)) = self.builtin_arg(args, index)? {
                if self.active_proxy_record(object_id)?.is_some() {
                    return Ok(true);
                }
                objects.push(object_id);
            }
        }
        for object_id in objects {
            let mut current = Some(object_id);
            for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
                let Some(id) = current else {
                    break;
                };
                if self.proxy_record(id)?.is_some() {
                    return Ok(true);
                }
                let Some(object) = self.heap.get(id.0 as usize) else {
                    break;
                };
                if object.contains_own_runtime_property(&key) {
                    return Ok(true);
                }
                current = self.observable_prototype_link(object, id);
            }
        }
        Ok(false)
    }

    /// The result of the Array.prototype method `kind` called on `object`
    /// (chosen by `generic_array_receiver`), or `None` when it has no
    /// generic path here.
    pub(super) fn array_method_generic(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        object: ObjectId,
        args: RegRange,
    ) -> Result<Option<Value>, InterpreterError> {
        use BuiltinFunctionKind as K;
        if matches!(
            kind,
            K::ArrayMap | K::ArrayFilter | K::ArraySliceMethod | K::ArraySplice | K::ArrayConcat
        ) {
            // Length, species constructors, element reads and callbacks can
            // each replace the pending result slot. Keep their observations
            // alive until every write to an arbitrary species result finishes.
            return self.generic_species_scope(|core| {
                core.array_method_generic_body(module, kind, object, args)
            });
        }
        self.array_method_generic_body(module, kind, object, args)
    }

    fn array_method_generic_body(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        object: ObjectId,
        args: RegRange,
    ) -> Result<Option<Value>, InterpreterError> {
        use BuiltinFunctionKind as K;
        // A collection request is for one guest call; none may run while
        // this method holds values in native locals.
        self.gc_nested_request = None;
        let m = Some(module);
        let o = object;
        let arg = |core: &Self, index: u32| -> Result<Value, InterpreterError> {
            Ok(core.builtin_arg(args, index)?.unwrap_or(Value::Undefined))
        };
        let value = match kind {
            K::ArrayPush => {
                let mut len = self.generic_length(m, o)?;
                if len + u64::from(args.count) > MAX_SAFE_LENGTH {
                    return Err(Self::generic_length_error());
                }
                for index in 0..args.count {
                    let item = arg(self, index)?;
                    self.generic_set(m, o, &Self::generic_index_key(len), item)?;
                    len += 1;
                }
                let length = Self::generic_length_value(len);
                self.generic_set(m, o, &Self::generic_length_key(), length.clone())?;
                length
            }
            K::ArrayPop => {
                let len = self.generic_length(m, o)?;
                if len == 0 {
                    self.generic_set(m, o, &Self::generic_length_key(), Value::Int(0))?;
                    Value::Undefined
                } else {
                    let key = Self::generic_index_key(len - 1);
                    let element = self.generic_get(m, o, &key)?;
                    self.generic_delete(m, o, &key)?;
                    let length = Self::generic_length_value(len - 1);
                    self.generic_set(m, o, &Self::generic_length_key(), length)?;
                    element
                }
            }
            K::ArrayShift => {
                let len = self.generic_length(m, o)?;
                if len == 0 {
                    self.generic_set(m, o, &Self::generic_length_key(), Value::Int(0))?;
                    Value::Undefined
                } else {
                    let first = self.generic_get(m, o, &Self::generic_index_key(0))?;
                    for k in 1..len {
                        self.generic_move(m, o, k, k - 1)?;
                    }
                    self.generic_delete(m, o, &Self::generic_index_key(len - 1))?;
                    let length = Self::generic_length_value(len - 1);
                    self.generic_set(m, o, &Self::generic_length_key(), length)?;
                    first
                }
            }
            K::ArrayUnshift => {
                let len = self.generic_length(m, o)?;
                let count = u64::from(args.count);
                if count > 0 {
                    if len + count > MAX_SAFE_LENGTH {
                        return Err(Self::generic_length_error());
                    }
                    for k in (1..=len).rev() {
                        self.generic_move(m, o, k - 1, k + count - 1)?;
                    }
                    for index in 0..args.count {
                        let item = arg(self, index)?;
                        self.generic_set(m, o, &Self::generic_index_key(u64::from(index)), item)?;
                    }
                }
                let length = Self::generic_length_value(len + count);
                self.generic_set(m, o, &Self::generic_length_key(), length.clone())?;
                length
            }
            K::ArraySplice => self.generic_splice(module, o, args)?,
            K::ArraySliceMethod => {
                let len = self.generic_length(m, o)?;
                let start = self.generic_relative_index(m, arg(self, 0)?, len, 0)?;
                let end = self.generic_relative_index(m, arg(self, 1)?, len, len)?;
                let result = self.array_species_result(module, o, end.saturating_sub(start))?;
                let mut n = 0u64;
                for k in start..end.max(start) {
                    let key = Self::generic_index_key(k);
                    if self.generic_has(m, o, &key)? {
                        let element = self.generic_get(m, o, &key)?;
                        self.generic_create_data_property(m, result, n, element)?;
                    }
                    n += 1;
                }
                self.generic_species_set_length(m, result, n)?;
                Value::Object(result)
            }
            K::ArrayConcat => {
                let mut items = vec![self.generic_object_value(o)];
                for index in 0..args.count {
                    items.push(arg(self, index)?);
                }
                let result = self.array_species_result(module, o, 0)?;
                let mut n = 0u64;
                for item in items {
                    let spreadable = match &item {
                        Value::Object(id) => self.generic_is_concat_spreadable(m, *id)?,
                        _ => false,
                    };
                    let Value::Object(source) = item else {
                        self.generic_create_data_property(m, result, n, item)?;
                        n += 1;
                        continue;
                    };
                    if !spreadable {
                        self.generic_create_data_property(m, result, n, item)?;
                        n += 1;
                        continue;
                    }
                    let len = self.generic_length(m, source)?;
                    if n + len > MAX_SAFE_LENGTH {
                        return Err(Self::generic_length_error());
                    }
                    for k in 0..len {
                        let key = Self::generic_index_key(k);
                        if self.generic_has(m, source, &key)? {
                            let element = self.generic_get(m, source, &key)?;
                            self.generic_create_data_property(m, result, n + k, element)?;
                        }
                    }
                    n += len;
                }
                self.generic_species_set_length(m, result, n)?;
                Value::Object(result)
            }
            K::ArrayIndexOf | K::ArrayLastIndexOf => {
                let len = self.generic_length(m, o)?;
                let search = arg(self, 0)?;
                let forward = kind == K::ArrayIndexOf;
                if len == 0 {
                    return Ok(Some(Value::Int(-1)));
                }
                let from = if forward {
                    self.generic_from_index(m, arg(self, 1)?, len, 0.0)?
                } else if args.count > 1 {
                    let n = self.generic_to_integer(m, arg(self, 1)?)?;
                    if n >= 0.0 {
                        n.min(len as f64 - 1.0)
                    } else {
                        len as f64 + n
                    }
                } else {
                    len as f64 - 1.0
                };
                let mut found = -1i64;
                if let Some(present) = self.generic_present_indices(o, len)? {
                    // A huge sparse array-like: only its present indices.
                    let first = from.max(0.0) as u64;
                    let candidates: Vec<u64> = if forward {
                        present.into_iter().filter(|&k| k >= first).collect()
                    } else if from >= 0.0 {
                        present
                            .into_iter()
                            .rev()
                            .filter(|&k| k <= from as u64)
                            .collect()
                    } else {
                        Vec::new()
                    };
                    for k in candidates {
                        let key = Self::generic_index_key(k);
                        if self.generic_has(m, o, &key)?
                            && Self::strict_eq_values(&self.generic_get(m, o, &key)?, &search)
                        {
                            found = k as i64;
                            break;
                        }
                    }
                } else if forward {
                    let mut k = from.max(0.0) as u64;
                    while k < len {
                        let key = Self::generic_index_key(k);
                        if self.generic_has(m, o, &key)?
                            && Self::strict_eq_values(&self.generic_get(m, o, &key)?, &search)
                        {
                            found = k as i64;
                            break;
                        }
                        k += 1;
                    }
                } else if from >= 0.0 {
                    let mut k = from as u64;
                    loop {
                        let key = Self::generic_index_key(k);
                        if self.generic_has(m, o, &key)?
                            && Self::strict_eq_values(&self.generic_get(m, o, &key)?, &search)
                        {
                            found = k as i64;
                            break;
                        }
                        if k == 0 {
                            break;
                        }
                        k -= 1;
                    }
                }
                Value::Int(found)
            }
            K::ArrayIncludes => {
                let len = self.generic_length(m, o)?;
                let search = arg(self, 0)?;
                if len == 0 {
                    return Ok(Some(Value::Bool(false)));
                }
                let mut k = self
                    .generic_from_index(m, arg(self, 1)?, len, 0.0)?
                    .max(0.0) as u64;
                let mut found = false;
                while k < len {
                    let element = self.generic_get(m, o, &Self::generic_index_key(k))?;
                    if Self::generic_same_value_zero(&element, &search) {
                        found = true;
                        break;
                    }
                    k += 1;
                }
                Value::Bool(found)
            }
            K::ArrayJoin => {
                let len = self.generic_length(m, o)?;
                let separator = match arg(self, 0)? {
                    Value::Undefined => ",".to_string(),
                    other => self.generic_to_string(m, other)?,
                };
                let mut out = String::new();
                for k in 0..len {
                    if k > 0 {
                        out.push_str(&separator);
                    }
                    let element = self.generic_get(m, o, &Self::generic_index_key(k))?;
                    if !element.is_nullish() {
                        out.push_str(&self.generic_to_string(m, element)?);
                    }
                    self.check_temporary_memory_budget(out.len() as u64)?;
                }
                Value::str(out)
            }
            K::ArrayToString => {
                let join =
                    self.generic_get(m, o, &RuntimePropertyKey::String(JsString::from("join")))?;
                if join.is_callable() {
                    self.invoke_inline_method_call(
                        m,
                        join,
                        self.generic_object_value(o),
                        Vec::new(),
                    )?
                } else if self.generic_is_array(o)? {
                    Value::str("[object Array]")
                } else {
                    self.object_prototype_to_string_value(&self.generic_object_value(o))
                }
            }
            K::ArrayReverse => {
                let len = self.generic_length(m, o)?;
                let middle = len / 2;
                for lower in 0..middle {
                    let upper = len - lower - 1;
                    let (lower_key, upper_key) = (
                        Self::generic_index_key(lower),
                        Self::generic_index_key(upper),
                    );
                    let lower_exists = self.generic_has(m, o, &lower_key)?;
                    let lower_value = if lower_exists {
                        self.generic_get(m, o, &lower_key)?
                    } else {
                        Value::Undefined
                    };
                    let upper_exists = self.generic_has(m, o, &upper_key)?;
                    let upper_value = if upper_exists {
                        self.generic_get(m, o, &upper_key)?
                    } else {
                        Value::Undefined
                    };
                    match (lower_exists, upper_exists) {
                        (true, true) => {
                            self.generic_set(m, o, &lower_key, upper_value)?;
                            self.generic_set(m, o, &upper_key, lower_value)?;
                        }
                        (false, true) => {
                            self.generic_set(m, o, &lower_key, upper_value)?;
                            self.generic_delete(m, o, &upper_key)?;
                        }
                        (true, false) => {
                            self.generic_delete(m, o, &lower_key)?;
                            self.generic_set(m, o, &upper_key, lower_value)?;
                        }
                        (false, false) => {}
                    }
                }
                self.generic_object_value(o)
            }
            // ES2020 23.1.3.3: the indices convert in order, then each element
            // moves with HasProperty/Get/Set or DeletePropertyOrThrow,
            // backwards when the ranges overlap with the target after the
            // source (bd-9vouw.276).
            K::ArrayCopyWithin => {
                let len = self.generic_length(m, o)?;
                let to = self.generic_relative_index(m, arg(self, 0)?, len, 0)?;
                let from = self.generic_relative_index(m, arg(self, 1)?, len, 0)?;
                let end = self.generic_relative_index(m, arg(self, 2)?, len, len)?;
                let count = end.saturating_sub(from).min(len - to);
                let backwards = from < to && to < from + count;
                for step in 0..count {
                    // A hole or a plain data element runs no guest code, so
                    // each step is metered here, as the native path metered
                    // holes before copyWithin moved to this generic loop
                    // (bd-9vouw.112): `a.length = 2 ** 32 - 1; a.copyWithin(0, 1)`
                    // otherwise ran ~4e9 uncharged steps.
                    self.charge_native_hole_read()?;
                    let (source, target) = if backwards {
                        (from + count - 1 - step, to + count - 1 - step)
                    } else {
                        (from + step, to + step)
                    };
                    let source_key = Self::generic_index_key(source);
                    let target_key = Self::generic_index_key(target);
                    if self.generic_has(m, o, &source_key)? {
                        let value = self.generic_get(m, o, &source_key)?;
                        self.generic_set(m, o, &target_key, value)?;
                    } else {
                        self.generic_delete(m, o, &target_key)?;
                    }
                }
                self.generic_object_value(o)
            }
            K::ArrayFill => {
                let len = self.generic_length(m, o)?;
                let value = arg(self, 0)?;
                let start = self.generic_relative_index(m, arg(self, 1)?, len, 0)?;
                let end = self.generic_relative_index(m, arg(self, 2)?, len, len)?;
                for k in start..end.max(start) {
                    self.generic_set(m, o, &Self::generic_index_key(k), value.clone())?;
                }
                self.generic_object_value(o)
            }
            K::ArrayAt => {
                let len = self.generic_length(m, o)?;
                let relative = self.generic_to_integer(m, arg(self, 0)?)?;
                let k = if relative >= 0.0 {
                    relative
                } else {
                    len as f64 + relative
                };
                if k < 0.0 || k >= len as f64 {
                    Value::Undefined
                } else {
                    self.generic_get(m, o, &Self::generic_index_key(k as u64))?
                }
            }
            K::ArrayForEach
            | K::ArrayMap
            | K::ArrayFilter
            | K::ArraySome
            | K::ArrayEvery
            | K::ArrayFind
            | K::ArrayFindIndex
            | K::ArrayFindLast
            | K::ArrayFindLastIndex => {
                let len = self.generic_length(m, o)?;
                let callback = arg(self, 0)?;
                if !callback.is_callable() {
                    return Err(InterpreterError::TypeError {
                        expected: "callable Array.prototype callback".to_string(),
                        got: callback.type_name().to_string(),
                    });
                }
                let this_arg = arg(self, 1)?;
                self.generic_iterate(module, o, kind, len, &callback, &this_arg)?
            }
            K::ArrayReduce | K::ArrayReduceRight => {
                let len = self.generic_length(m, o)?;
                let callback = arg(self, 0)?;
                if !callback.is_callable() {
                    return Err(InterpreterError::TypeError {
                        expected: "callable Array.prototype.reduce callback".to_string(),
                        got: callback.type_name().to_string(),
                    });
                }
                let backwards = kind == K::ArrayReduceRight;
                let mut indices: Box<dyn Iterator<Item = u64>> =
                    match self.generic_present_indices(o, len)? {
                        Some(present) if backwards => Box::new(present.into_iter().rev()),
                        Some(present) => Box::new(present.into_iter()),
                        None => Box::new(
                            (0..len).map(move |step| if backwards { len - 1 - step } else { step }),
                        ),
                    };
                let mut accumulator = if args.count > 1 {
                    Some(arg(self, 1)?)
                } else {
                    None
                };
                if accumulator.is_none() {
                    for k in indices.by_ref() {
                        let key = Self::generic_index_key(k);
                        if self.generic_has(m, o, &key)? {
                            accumulator = Some(self.generic_get(m, o, &key)?);
                            break;
                        }
                    }
                }
                let Some(mut accumulator) = accumulator else {
                    return Err(InterpreterError::TypeError {
                        expected: "non-empty array or initial value".to_string(),
                        got: "empty Array.prototype.reduce without initialValue".to_string(),
                    });
                };
                for k in indices {
                    let key = Self::generic_index_key(k);
                    if self.generic_has(m, o, &key)? {
                        let element = self.generic_get(m, o, &key)?;
                        accumulator = self.invoke_inline_method_call(
                            m,
                            callback.clone(),
                            Value::Undefined,
                            vec![
                                accumulator,
                                element,
                                Self::generic_length_value(k),
                                self.generic_object_value(o),
                            ],
                        )?;
                    }
                }
                accumulator
            }
            K::ArraySort | K::ArrayToSorted => {
                let comparator = arg(self, 0)?;
                if !matches!(comparator, Value::Undefined) && !comparator.is_callable() {
                    return Err(InterpreterError::TypeError {
                        expected: "undefined or callable comparator".to_string(),
                        got: comparator.type_name().to_string(),
                    });
                }
                let len = self.generic_length(m, o)?;
                let in_place = kind == K::ArraySort;
                let mut items = self.generic_buffer(len)?;
                for k in 0..len {
                    let key = Self::generic_index_key(k);
                    // toSorted reads holes as undefined; sort skips them.
                    if !in_place || self.generic_has(m, o, &key)? {
                        items.push(self.generic_get(m, o, &key)?);
                    }
                }
                let sorted = self.generic_merge_sort(m, items, &comparator)?;
                if in_place {
                    let count = sorted.len() as u64;
                    for (k, item) in sorted.into_iter().enumerate() {
                        self.generic_set(m, o, &Self::generic_index_key(k as u64), item)?;
                    }
                    for k in count..len {
                        self.generic_delete(m, o, &Self::generic_index_key(k))?;
                    }
                    self.generic_object_value(o)
                } else {
                    Value::Object(self.alloc_array_from_values(&sorted)?)
                }
            }
            K::ArrayToReversed => {
                let len = self.generic_length(m, o)?;
                let mut items = self.generic_buffer(len)?;
                for k in (0..len).rev() {
                    items.push(self.generic_get(m, o, &Self::generic_index_key(k))?);
                }
                Value::Object(self.alloc_array_from_values(&items)?)
            }
            K::ArrayWith => {
                let len = self.generic_length(m, o)?;
                let relative = self.generic_to_integer(m, arg(self, 0)?)?;
                let actual = if relative >= 0.0 {
                    relative
                } else {
                    len as f64 + relative
                };
                if actual < 0.0 || actual >= len as f64 {
                    return Err(InterpreterError::RangeError {
                        message: "Invalid index for Array.prototype.with".to_string(),
                    });
                }
                let replacement = arg(self, 1)?;
                let mut items = self.generic_buffer(len)?;
                for k in 0..len {
                    items.push(if k == actual as u64 {
                        replacement.clone()
                    } else {
                        self.generic_get(m, o, &Self::generic_index_key(k))?
                    });
                }
                Value::Object(self.alloc_array_from_values(&items)?)
            }
            K::ArrayKeys | K::ArrayValues | K::ArrayEntries => {
                let len = self.generic_length(m, o)?;
                let mut items = self.generic_buffer(len)?;
                for k in 0..len {
                    let index = Self::generic_length_value(k);
                    items.push(match kind {
                        K::ArrayKeys => index,
                        K::ArrayValues => self.generic_get(m, o, &Self::generic_index_key(k))?,
                        _ => {
                            let element = self.generic_get(m, o, &Self::generic_index_key(k))?;
                            Value::Object(self.alloc_array_from_values(&[index, element])?)
                        }
                    });
                }
                let trace_index = self.start_iteration_trace(IterationKind::ForOf, || {
                    format!("array_iterator:proxy|{}", o.0)
                });
                let handle =
                    self.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
                        values: items,
                        next_index: 0,
                        array: None,
                        typed_array: None,
                        collection: None,
                        iterator_receiver: None,
                        next_method: None,
                        timers_interval: None,
                        done: false,
                        closed: false,
                        return_called: false,
                        trace_index,
                    }))?;
                Value::Iterator(handle)
            }
            _ => return Ok(None),
        };
        Ok(Some(value))
    }

    /// ES2020 23.1.3.28 Array.prototype.splice over [[Get]]/[[Set]]/[[Delete]].
    fn generic_splice(
        &mut self,
        module: &Ir3Module,
        o: ObjectId,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let m = Some(module);
        let len = self.generic_length(m, o)?;
        let start_arg = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let start = self.generic_relative_index(m, start_arg, len, 0)?;
        let delete_count = match args.count {
            0 => 0,
            1 => len - start,
            _ => {
                let requested = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let requested = self.generic_to_integer(m, requested)?;
                requested.clamp(0.0, (len - start) as f64) as u64
            }
        };
        let mut items = Vec::new();
        for index in 2..args.count.max(2) {
            items.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
        }
        let item_count = items.len() as u64;
        if len + item_count - delete_count > MAX_SAFE_LENGTH {
            return Err(Self::generic_length_error());
        }
        let removed = self.array_species_result(module, o, delete_count)?;
        for k in 0..delete_count {
            let key = Self::generic_index_key(start + k);
            if self.generic_has(m, o, &key)? {
                let element = self.generic_get(m, o, &key)?;
                self.generic_create_data_property(m, removed, k, element)?;
            }
        }
        self.generic_species_set_length(m, removed, delete_count)?;
        if item_count < delete_count {
            for k in start..(len - delete_count) {
                self.generic_move(m, o, k + delete_count, k + item_count)?;
            }
            for k in ((len - delete_count + item_count)..len).rev() {
                self.generic_delete(m, o, &Self::generic_index_key(k))?;
            }
        } else if item_count > delete_count {
            for k in (start..(len - delete_count)).rev() {
                self.generic_move(m, o, k + delete_count, k + item_count)?;
            }
        }
        for (offset, item) in items.into_iter().enumerate() {
            self.generic_set(m, o, &Self::generic_index_key(start + offset as u64), item)?;
        }
        let length = Self::generic_length_value(len - delete_count + item_count);
        self.generic_set(m, o, &Self::generic_length_key(), length)?;
        Ok(Value::Object(removed))
    }

    /// forEach, map, filter, some, every and the find family.
    fn generic_iterate(
        &mut self,
        module: &Ir3Module,
        o: ObjectId,
        kind: BuiltinFunctionKind,
        len: u64,
        callback: &Value,
        this_arg: &Value,
    ) -> Result<Value, InterpreterError> {
        use BuiltinFunctionKind as K;
        let m = Some(module);
        let result = match kind {
            K::ArrayMap => Some(self.array_species_result(module, o, len)?),
            K::ArrayFilter => Some(self.array_species_result(module, o, 0)?),
            _ => None,
        };
        let backwards = matches!(kind, K::ArrayFindLast | K::ArrayFindLastIndex);
        // The find family visits every index; the others skip holes.
        let visits_holes = matches!(
            kind,
            K::ArrayFind | K::ArrayFindIndex | K::ArrayFindLast | K::ArrayFindLastIndex
        );
        let mut filtered = 0u64;
        // A hole-skipping method over a huge sparse array-like visits only the
        // indices present (generic_present_indices); each is re-checked below.
        let present = if visits_holes {
            None
        } else {
            self.generic_present_indices(o, len)?
        };
        let steps: Box<dyn Iterator<Item = u64>> = match present {
            Some(indices) => Box::new(indices.into_iter()),
            None => {
                Box::new((0..len).map(move |step| if backwards { len - 1 - step } else { step }))
            }
        };
        for k in steps {
            let key = Self::generic_index_key(k);
            if !visits_holes && !self.generic_has(m, o, &key)? {
                continue;
            }
            let element = self.generic_get(m, o, &key)?;
            let outcome = self.invoke_inline_method_call(
                m,
                callback.clone(),
                this_arg.clone(),
                vec![
                    element.clone(),
                    Self::generic_length_value(k),
                    self.generic_object_value(o),
                ],
            )?;
            match kind {
                K::ArrayMap => {
                    let result = result.expect("map allocates its result");
                    self.generic_create_data_property(m, result, k, outcome)?;
                }
                K::ArrayFilter if outcome.is_truthy() => {
                    let result = result.expect("filter allocates its result");
                    self.generic_create_data_property(m, result, filtered, element)?;
                    filtered += 1;
                }
                K::ArraySome if outcome.is_truthy() => return Ok(Value::Bool(true)),
                K::ArrayEvery if !outcome.is_truthy() => return Ok(Value::Bool(false)),
                K::ArrayFind | K::ArrayFindLast if outcome.is_truthy() => return Ok(element),
                K::ArrayFindIndex | K::ArrayFindLastIndex if outcome.is_truthy() => {
                    return Ok(Self::generic_length_value(k));
                }
                _ => {}
            }
        }
        Ok(match kind {
            K::ArrayMap | K::ArrayFilter => {
                let result = result.expect("map and filter allocate their result");
                Value::Object(result)
            }
            K::ArraySome => Value::Bool(false),
            K::ArrayEvery => Value::Bool(true),
            K::ArrayFindIndex | K::ArrayFindLastIndex => Value::Int(-1),
            _ => Value::Undefined,
        })
    }

    /// A stable merge sort with ES2020 23.1.3.27.1 SortCompare: undefined
    /// last, the comparator's ToNumber result (NaN is 0), else the UTF-16
    /// order of ToString.
    fn generic_merge_sort(
        &mut self,
        m: Option<&Ir3Module>,
        items: Vec<Value>,
        comparator: &Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        if items.len() <= 1 {
            return Ok(items);
        }
        let mut right = items;
        let left = right.drain(..right.len() / 2).collect();
        let left = self.generic_merge_sort(m, left, comparator)?;
        let right = self.generic_merge_sort(m, right, comparator)?;
        let mut merged = Vec::with_capacity(left.len() + right.len());
        let (mut left, mut right) = (left.into_iter().peekable(), right.into_iter().peekable());
        while let (Some(a), Some(b)) = (left.peek(), right.peek()) {
            let ordering = self.generic_sort_compare(m, a.clone(), b.clone(), comparator)?;
            if ordering == Ordering::Greater {
                merged.extend(right.next());
            } else {
                merged.extend(left.next());
            }
        }
        merged.extend(left);
        merged.extend(right);
        Ok(merged)
    }

    fn generic_sort_compare(
        &mut self,
        m: Option<&Ir3Module>,
        a: Value,
        b: Value,
        comparator: &Value,
    ) -> Result<Ordering, InterpreterError> {
        match (matches!(a, Value::Undefined), matches!(b, Value::Undefined)) {
            (true, true) => return Ok(Ordering::Equal),
            (true, false) => return Ok(Ordering::Greater),
            (false, true) => return Ok(Ordering::Less),
            (false, false) => {}
        }
        if comparator.is_callable() {
            let result = self.invoke_inline_method_call(
                m,
                comparator.clone(),
                Value::Undefined,
                vec![a, b],
            )?;
            let number = self.generic_to_number(m, result)?;
            return Ok(number.partial_cmp(&0.0).unwrap_or(Ordering::Equal));
        }
        let (a, b) = (self.generic_to_string(m, a)?, self.generic_to_string(m, b)?);
        Ok(a.encode_utf16().cmp(b.encode_utf16()))
    }

    /// IsArray (ES2020 7.2.2), looking through proxies to their targets;
    /// Array.prototype is itself an Array exotic object.
    pub(super) fn generic_is_array(&self, object: ObjectId) -> Result<bool, InterpreterError> {
        let mut current = object;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            if let Some((target, _handler)) = self.active_proxy_record(current)? {
                current = target;
                continue;
            }
            return Ok(self
                .heap
                .get(current.0 as usize)
                .is_some_and(|object| object.is_array)
                || self.builtin_prototypes.get("Array") == Some(&current));
        }
        Err(InterpreterError::TypeError {
            expected: "bounded Proxy target chain".to_string(),
            got: format!("depth {MAX_PROTOTYPE_CHAIN_DEPTH}"),
        })
    }

    /// The indices below `len` at which HasProperty(o, k) holds, ascending,
    /// when `len` is huge and they can be read without running guest code:
    /// `o` and its prototype chain are ordinary objects (no Proxy, Array,
    /// typed array or wrapper) and only `o` has integer keys, so the present
    /// indices are its own integer keys (accessors included). Probing every
    /// index of `{ length: 2 ** 32 }` ran out of budget where Node answers
    /// at once. `None`: probe each index.
    fn generic_present_indices(
        &self,
        o: ObjectId,
        len: u64,
    ) -> Result<Option<Vec<u64>>, InterpreterError> {
        const SPARSE_SCAN_MIN_LENGTH: u64 = 1 << 16;
        if len < SPARSE_SCAN_MIN_LENGTH {
            return Ok(None);
        }
        let mut indices = Vec::new();
        let mut current = Some(o);
        for depth in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else {
                break;
            };
            if self.proxy_record(id)?.is_some() {
                return Ok(None);
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                return Ok(None);
            };
            if object.is_array || object.typed_array.is_some() || object.primitive_value.is_some() {
                return Ok(None);
            }
            for key in object.properties.keys() {
                let Ok(index) = key.parse::<u64>() else {
                    continue;
                };
                if index.to_string() != *key || index >= len {
                    continue;
                }
                if depth > 0 {
                    return Ok(None);
                }
                indices.push(index);
            }
            current = self.observable_prototype_link(object, id);
        }
        if current.is_some() {
            return Ok(None);
        }
        indices.sort_unstable();
        Ok(Some(indices))
    }

    /// A buffer for up to `len` elements, charged to the temporary budget
    /// first: the length is guest-chosen, up to 2^53 - 1.
    fn generic_buffer(&self, len: u64) -> Result<Vec<Value>, InterpreterError> {
        self.element_buffer(usize::try_from(len).unwrap_or(usize::MAX))
    }

    /// IsConcatSpreadable (ES2020 22.1.3.1.1): a defined @@isConcatSpreadable
    /// decides, else IsArray.
    fn generic_is_concat_spreadable(
        &mut self,
        m: Option<&Ir3Module>,
        o: ObjectId,
    ) -> Result<bool, InterpreterError> {
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::IsConcatSpreadable.id());
        match self.generic_get(m, o, &key)? {
            Value::Undefined => self.generic_is_array(o),
            spreadable => Ok(spreadable.is_truthy()),
        }
    }

    pub(super) fn generic_index_key(index: u64) -> RuntimePropertyKey {
        RuntimePropertyKey::String(JsString::from(index.to_string()))
    }

    fn generic_key_name(key: &RuntimePropertyKey) -> String {
        match key {
            RuntimePropertyKey::String(name) => name.to_string(),
            RuntimePropertyKey::Symbol(_) => "(symbol)".to_string(),
        }
    }

    fn generic_length_key() -> RuntimePropertyKey {
        RuntimePropertyKey::String(JsString::from("length"))
    }

    fn generic_length_value(length: u64) -> Value {
        Value::Int(i64::try_from(length).unwrap_or(i64::MAX))
    }

    fn generic_length_error() -> InterpreterError {
        InterpreterError::TypeError {
            expected: "array length at most 2^53 - 1".to_string(),
            got: "a longer result".to_string(),
        }
    }

    /// [[Get]](O, P). IFC: the stored label of the property read joins the
    /// pending result label, as GetProperty's does (bd-ojvo1).
    /// The algorithm's O for the generic receiver `o`: the function whose
    /// own-property object `o` is, when the method runs on a function
    /// (bd-9vouw.285), else `o` itself.
    fn generic_object_value(&self, o: ObjectId) -> Value {
        match &self.generic_function_receiver {
            Some((object, function)) if *object == o => function.clone(),
            _ => Value::Object(o),
        }
    }

    pub(super) fn generic_get(
        &mut self,
        m: Option<&Ir3Module>,
        o: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<Value, InterpreterError> {
        let stored = self.runtime_property_label(o, key);
        if stored != Label::Public {
            let joined = self
                .pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public)
                .join(&stored);
            self.replace_pending_hostcall_result_label(Some(joined))?;
        }
        self.proxy_aware_get_runtime_property(m, o, key, self.generic_object_value(o), 0)
    }

    /// CreateDataPropertyOrThrow on a species result. Species may return a
    /// Proxy or an object with an existing property: defining an element
    /// uses [[DefineOwnProperty]], never [[Set]] or an inherited setter.
    fn generic_create_data_property(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        index: u64,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let fields = PropertyDescriptorFields {
            value: Some(value),
            writable: Some(true),
            get: None,
            set: None,
            enumerable: Some(true),
            configurable: Some(true),
        };
        let key = Self::generic_index_key(index);
        self.generic_species_output_write(object, &key, |core| {
            if core.proxy_aware_define_own_property(module, object, key.clone(), fields, 0)? {
                Ok(())
            } else {
                Err(InterpreterError::TypeError {
                    expected: "definable element on an Array species result".to_string(),
                    got: "a refused [[DefineOwnProperty]]".to_string(),
                })
            }
        })
    }

    fn generic_species_set_length(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        length: u64,
    ) -> Result<(), InterpreterError> {
        let key = Self::generic_length_key();
        self.generic_species_output_write(object, &key, |core| {
            core.generic_set(module, object, &key, Self::generic_length_value(length))
        })
    }

    /// A species can return an existing public alias. Admit its mutation
    /// label before guest code can write, including through Proxy targets,
    /// and retain observations when a later definition or length write fails.
    /// The scoped callback floor also protects values handed to destination
    /// traps whose nested calls replace the pending result label.
    fn generic_species_output_write(
        &mut self,
        object: ObjectId,
        key: &RuntimePropertyKey,
        write: impl FnOnce(&mut Self) -> Result<(), InterpreterError>,
    ) -> Result<(), InterpreterError> {
        self.generic_species_scope(|core| {
            core.generic_species_admit_output_label(object, key)?;
            let outcome = write(core);
            core.observe_scoped_callback_result()?;
            // A trap may mutate its target before returning false or throwing.
            core.generic_species_admit_output_label(object, key)?;
            outcome
        })
    }

    fn generic_species_admit_output_label(
        &mut self,
        object: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        self.reflect_admit_mutation_label(object)?;
        let label = self.json_parse_context_label()?;
        let bytes = Self::estimate_label_bytes(&label);
        self.json_reserve_temporary(bytes)?;
        let outcome = (|| {
            let mut current = object;
            for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
                self.json_charge_work()?;
                let previous = self.own_stored_runtime_property_label(current, key);
                let stored = self.join_owned_label_with_temporary_budget(previous, &label)?;
                let stored_bytes = Self::estimate_label_bytes(&stored);
                self.json_reserve_temporary(stored_bytes)?;
                let outcome = self.set_own_runtime_property_label(current, key, &stored);
                drop(stored);
                self.json_release_temporary(stored_bytes);
                outcome?;
                match self.proxy_record(current)? {
                    Some((target, _, false)) => current = target,
                    _ => return Ok(()),
                }
            }
            Err(InterpreterError::StackOverflow {
                depth: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
                max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
            })
        })();
        drop(label);
        self.json_release_temporary(bytes);
        outcome
    }

    fn generic_species_scope<T>(
        &mut self,
        step: impl FnOnce(&mut Self) -> Result<T, InterpreterError>,
    ) -> Result<T, InterpreterError> {
        self.scoped_conversion(|core| {
            let label = core.json_parse_context_label()?;
            core.json_observe_label(label)?;
            let mut outcome = step(core);
            if let Err(error) = core.observe_scoped_callback_result() {
                outcome = Err(error);
            }
            match outcome {
                Err(error) if Self::js_catchable_error_name(&error).is_some() => {
                    Err(core.scoped_native_error(&error)?)
                }
                Err(error @ InterpreterError::UncaughtException { .. }) => {
                    let label = core.json_parse_context_label()?;
                    core.join_pending_exception_label(&label)?;
                    Err(error)
                }
                other => other,
            }
        })
    }

    /// Set(O, P, V, true): a refused write is a TypeError.
    fn generic_set(
        &mut self,
        m: Option<&Ir3Module>,
        o: ObjectId,
        key: &RuntimePropertyKey,
        value: Value,
    ) -> Result<(), InterpreterError> {
        if self.proxy_aware_set_runtime_property(
            m,
            o,
            key,
            value,
            self.generic_object_value(o),
            0,
        )? {
            Ok(())
        } else {
            Err(InterpreterError::TypeError {
                expected: format!("writable property {}", Self::generic_key_name(key)),
                got: "a refused [[Set]]".to_string(),
            })
        }
    }

    fn generic_has(
        &mut self,
        m: Option<&Ir3Module>,
        o: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        self.proxy_aware_has_runtime_property(m, o, key, 0)
    }

    /// DeletePropertyOrThrow.
    fn generic_delete(
        &mut self,
        m: Option<&Ir3Module>,
        o: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        if self.proxy_aware_delete_runtime_property(m, o, key, 0)? {
            Ok(())
        } else {
            Err(InterpreterError::TypeError {
                expected: format!("configurable property {}", Self::generic_key_name(key)),
                got: "a refused [[Delete]]".to_string(),
            })
        }
    }

    /// Move element `from` to `to`, or delete `to` when `from` is a hole.
    fn generic_move(
        &mut self,
        m: Option<&Ir3Module>,
        o: ObjectId,
        from: u64,
        to: u64,
    ) -> Result<(), InterpreterError> {
        let (from_key, to_key) = (Self::generic_index_key(from), Self::generic_index_key(to));
        if self.generic_has(m, o, &from_key)? {
            let value = self.generic_get(m, o, &from_key)?;
            self.generic_set(m, o, &to_key, value)
        } else {
            self.generic_delete(m, o, &to_key)
        }
    }

    /// LengthOfArrayLike: ToLength(Get(O, "length")).
    pub(super) fn generic_length(
        &mut self,
        m: Option<&Ir3Module>,
        o: ObjectId,
    ) -> Result<u64, InterpreterError> {
        let length = self.generic_get(m, o, &Self::generic_length_key())?;
        let number = self.generic_to_integer(m, length)?;
        Ok(number.clamp(0.0, MAX_SAFE_LENGTH as f64) as u64)
    }

    fn generic_to_number(
        &mut self,
        m: Option<&Ir3Module>,
        value: Value,
    ) -> Result<f64, InterpreterError> {
        let primitive = if value.is_object_like() {
            self.coerce_runtime_primitive(m, value, false)?
        } else {
            value
        };
        Self::coerce_to_float(&primitive).ok_or_else(|| InterpreterError::TypeError {
            expected: "value convertible to a number".to_string(),
            got: primitive.type_name().to_string(),
        })
    }

    /// ToIntegerOrInfinity.
    fn generic_to_integer(
        &mut self,
        m: Option<&Ir3Module>,
        value: Value,
    ) -> Result<f64, InterpreterError> {
        let number = self.generic_to_number(m, value)?;
        Ok(if number.is_nan() { 0.0 } else { number.trunc() })
    }

    /// A relative start or end (slice, splice, fill): `undefined` is `default`.
    fn generic_relative_index(
        &mut self,
        m: Option<&Ir3Module>,
        value: Value,
        len: u64,
        default: u64,
    ) -> Result<u64, InterpreterError> {
        if matches!(value, Value::Undefined) {
            return Ok(default);
        }
        let relative = self.generic_to_integer(m, value)?;
        Ok(if relative < 0.0 {
            (len as f64 + relative).max(0.0) as u64
        } else {
            relative.min(len as f64) as u64
        })
    }

    /// indexOf/includes fromIndex: the first index to examine (may be past
    /// the end).
    fn generic_from_index(
        &mut self,
        m: Option<&Ir3Module>,
        value: Value,
        len: u64,
        default: f64,
    ) -> Result<f64, InterpreterError> {
        let n = if matches!(value, Value::Undefined) {
            default
        } else {
            self.generic_to_integer(m, value)?
        };
        Ok(if n >= 0.0 {
            n
        } else {
            (len as f64 + n).max(0.0)
        })
    }

    fn generic_to_string(
        &mut self,
        m: Option<&Ir3Module>,
        value: Value,
    ) -> Result<String, InterpreterError> {
        let primitive = if value.is_object_like() {
            self.coerce_runtime_primitive(m, value, true)?
        } else {
            value
        };
        if matches!(primitive, Value::Symbol(_)) {
            return Err(Self::symbol_to_string_error());
        }
        Ok(self.value_to_string(&primitive))
    }

    /// Array.prototype.toLocaleString (ES2020 22.1.3.27; %TypedArray%'s,
    /// 22.2.3.28, after its receiver check): each element's toLocaleString
    /// (Invoke), ToString'd, "," between, undefined and null as "". It did
    /// not exist (`[1234].toLocaleString()` threw); the typed array one was
    /// an "unsupported TypedArray method" TypeError.
    pub(super) fn array_to_locale_string(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let o = match receiver {
            Value::Object(object_id) => object_id,
            Value::Undefined | Value::Null => {
                return Err(InterpreterError::TypeError {
                    expected: "object-coercible this for Array.prototype.toLocaleString"
                        .to_string(),
                    got: receiver.type_name().to_string(),
                });
            }
            other if other.is_object_like() => {
                return Err(InterpreterError::TypeError {
                    expected: "array-like this for Array.prototype.toLocaleString".to_string(),
                    got: other.type_name().to_string(),
                });
            }
            primitive => self.alloc_primitive_wrapper(primitive)?,
        };
        let m = Some(module);
        let len = self.generic_length(m, o)?;
        // The separators alone must fit: a huge length fails here, not after
        // a long walk.
        self.check_string_limit(usize::try_from(len.saturating_sub(1)).unwrap_or(usize::MAX))?;
        let to_locale_string = RuntimePropertyKey::String(JsString::from("toLocaleString"));
        let mut out = String::new();
        for k in 0..len {
            if k > 0 {
                out.push(',');
            }
            let element = self.generic_get(m, o, &Self::generic_index_key(k))?;
            if matches!(element, Value::Undefined | Value::Null) {
                // No guest call runs for it, so the step is metered here
                // (bd-9vouw.112).
                self.charge_native_hole_read()?;
                continue;
            }
            let method = self.get_v(module, &element, &to_locale_string)?;
            if !method.is_callable() {
                return Err(InterpreterError::TypeError {
                    expected: "callable toLocaleString of an element".to_string(),
                    got: method.type_name().to_string(),
                });
            }
            let result = self.call_conversion_method(module, method, &element, Vec::new())?;
            let text = self.generic_to_string(m, result)?;
            self.check_string_limit(out.len().saturating_add(text.len()))?;
            out.push_str(&text);
        }
        Ok(Value::str(out))
    }

    fn generic_same_value_zero(a: &Value, b: &Value) -> bool {
        let is_nan = |value: &Value| matches!(value, Value::Float(f) if f.inner().is_nan());
        Self::strict_eq_values(a, b) || (is_nan(a) && is_nan(b))
    }
}
