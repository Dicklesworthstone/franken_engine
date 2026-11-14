use super::*;

impl InterpreterCore {
    /// Unified Math.random implementation - deterministic with proper [0,1) range.
    pub(super) fn math_random_impl(&mut self) -> Result<Value, InterpreterError> {
        // Generate deterministic pseudo-random number using execution state as seed
        use crate::security_e2e::Xorshift64;
        use sha2::{Digest, Sha256};

        // Create deterministic seed from execution state using stable hash
        // (SHA-256 is deterministic across builds, unlike DefaultHasher)
        let mut digest = Sha256::new();
        digest.update((self.call_stack.len() as u64).to_le_bytes());
        digest.update((self.heap.len() as u64).to_le_bytes());
        digest.update(self.instructions_executed.to_le_bytes());
        digest.update((self.ip as u64).to_le_bytes());

        let hash_result = digest.finalize();
        let seed = u64::from_le_bytes([
            hash_result[0],
            hash_result[1],
            hash_result[2],
            hash_result[3],
            hash_result[4],
            hash_result[5],
            hash_result[6],
            hash_result[7],
        ]);
        let mut rng = Xorshift64::new(seed);

        // Generate random value in [0, 1) using 53-bit precision to avoid rounding to 1.0
        // JavaScript Number uses IEEE 754 double precision with 53-bit significand
        let random_bits = rng.next_u64() >> 11; // Use top 53 bits
        let normalized = (random_bits as f64) / (1u64 << 53) as f64;

        Ok(Value::Float(Float64::new(normalized)))
    }

    pub(super) fn optional_number_hostcall_integer_arg(
        &self,
        args: RegRange,
        index: u32,
    ) -> Result<Option<i64>, InterpreterError> {
        match self.builtin_arg(args, index)? {
            Some(Value::Undefined) | None => Ok(None),
            Some(value) => Ok(Some(Self::value_as_integer(&value))),
        }
    }

    /// Coerce a primitive to its exact [`JsString`] for the legacy string
    /// dispatch arms: a string value keeps its exact code units (lone
    /// surrogates included) instead of routing through the lossy projection;
    /// other primitives use their canonical spelling. `None` for the values
    /// those arms treat as non-coercible (objects, functions). (bd-rdnhc)
    pub(super) fn legacy_string_arm_operand(value: &Value) -> Option<JsString> {
        match value {
            Value::Str(s) => Some(s.clone()),
            Value::Int(i) => Some(JsString::from(i.to_string())),
            Value::Float(f) => Some(JsString::from(f.inner().to_string())),
            Value::Bool(b) => Some(JsString::from(b.to_string())),
            Value::Null => Some(JsString::from("null")),
            Value::Undefined => Some(JsString::from("undefined")),
            _ => None,
        }
    }

    /// Coerce a search-string builtin argument to its exact [`JsString`]
    /// (preserving lone surrogates); a missing argument is the literal
    /// `"undefined"` per ToString(undefined). (bd-rdnhc)
    pub(super) fn builtin_search_js_string(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        index: u32,
    ) -> Result<JsString, InterpreterError> {
        // bd-9vouw.117: an object argument converts through its own
        // toString/valueOf (`'abc'.indexOf({ toString() { return 'b' } })`).
        Ok(match self.builtin_string_arg(module, args, index)? {
            Some(Value::Str(s)) => s,
            // ES2020 7.1.12 ToString: a Symbol throws (`'a'.endsWith(Symbol())`).
            Some(Value::Symbol(_)) => return Err(Self::symbol_to_string_error()),
            Some(other) => JsString::from(self.value_to_string(&other)),
            None => JsString::from("undefined"),
        })
    }

    /// ES2020 7.1.12: ToString of a Symbol is a TypeError (only `String(sym)`
    /// and `sym.toString()` produce `Symbol(description)`).
    pub(super) fn symbol_to_string_error() -> InterpreterError {
        InterpreterError::TypeError {
            expected: "value convertible to a string".to_string(),
            got: "Symbol (Cannot convert a Symbol value to a string)".to_string(),
        }
    }

    /// Where a collection constructor reads its seed values (ES2020
    /// 23.1.1.1, 23.2.1.1, 23.3.1.1, 23.4.1.1): `undefined` and `null` seed
    /// nothing, and anything else goes through the for-of iteration
    /// protocol, so another Map or Set, a generator, a `keys()`/`values()`
    /// iterator or a user iterable all seed, and a non-iterable is a
    /// TypeError. (Seeding read indexed properties instead, so
    /// `new Set(otherSet)` and `new Map(generator())` were silently empty.)
    pub(super) fn collection_seed_source(
        &mut self,
        module: Option<&Ir3Module>,
        iterable: Value,
    ) -> Result<CollectionSeedSource, InterpreterError> {
        if matches!(iterable, Value::Undefined | Value::Null) {
            return Ok(CollectionSeedSource::Values(Vec::new().into_iter()));
        }
        // An array iterated by the builtin %Array.prototype.values% yields
        // its elements (holes as undefined) with no observable step, so read
        // them without allocating an iterator.
        if let Value::Object(array_id) = iterable
            && self
                .heap
                .get(array_id.0 as usize)
                .is_some_and(|object| object.is_array)
            && !self.array_from_has_explicit_iterator(array_id)?
        {
            let values = self.array_like_values(array_id)?;
            return Ok(CollectionSeedSource::Values(values.into_iter()));
        }
        Ok(CollectionSeedSource::Iterator(
            self.init_for_of_iterator(module, iterable)?,
        ))
    }

    /// The next seed value; entries are validated one at a time, as they
    /// are produced, so an invalid entry stops even an endless iterator.
    pub(super) fn next_collection_seed(
        &mut self,
        module: Option<&Ir3Module>,
        source: &mut CollectionSeedSource,
    ) -> Result<Option<Value>, InterpreterError> {
        match source {
            CollectionSeedSource::Values(values) => Ok(values.next()),
            CollectionSeedSource::Iterator(iterator) => {
                self.advance_for_of_iterator(module, iterator.clone())
            }
        }
    }

    /// An entry the constructor rejects ends the seeding with IteratorClose
    /// (the iterator's `return`), then the error.
    pub(super) fn close_collection_seed<T>(
        &mut self,
        module: Option<&Ir3Module>,
        source: CollectionSeedSource,
        error: InterpreterError,
    ) -> Result<T, InterpreterError> {
        match source {
            CollectionSeedSource::Values(_) => Err(error),
            CollectionSeedSource::Iterator(iterator) => {
                self.array_from_close_after_error(module, iterator, error)
            }
        }
    }

    /// Fold the pending hostcall label (a yielded value's, or an entry
    /// read's) into `label`, as ForOfNext does for a loop variable, so the
    /// seeded collection carries what flowed into it; `finish_collection_seed`
    /// hands the join back as the constructor's result label.
    pub(super) fn observe_collection_seed_label(&mut self, label: &mut Label) {
        if let Some(observed) = self.take_pending_hostcall_result_label() {
            *label = label.join(&observed);
        }
    }

    pub(super) fn finish_collection_seed(&mut self, label: Label) -> Result<(), InterpreterError> {
        self.replace_pending_hostcall_result_label(Some(label))
    }

    /// `Get(entry, "0")` and `Get(entry, "1")` of a Map or WeakMap seed
    /// entry, which must be an object (ES2020 23.1.1.2
    /// AddEntriesFromIterable): `new Map(['ab'])` is a TypeError, and an
    /// array-like `{ 0: k, 1: v }` is an entry.
    pub(super) fn collection_seed_entry(
        &mut self,
        module: Option<&Ir3Module>,
        entry: &Value,
    ) -> Result<(Value, Value), InterpreterError> {
        if !entry.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "entry object ([key, value]) in the Map iterable".to_string(),
                got: entry.type_name().to_string(),
            });
        }
        // A function entry has no "0" or "1" unless a program set them.
        let Value::Object(entry_id) = entry else {
            return Ok((Value::Undefined, Value::Undefined));
        };
        let key = self.proxy_aware_get_property(module, *entry_id, "0", entry.clone(), 0)?;
        let value = self.proxy_aware_get_property(module, *entry_id, "1", entry.clone(), 0)?;
        Ok((key, value))
    }

    /// The adder a Map, Set, WeakMap or WeakSet constructor (`type_tag`)
    /// calls for each element of its iterable (ES2020 23.1.1.1, 23.2.1.1,
    /// 23.3.1.1, 23.4.1.1 step 5): Get(collection, "set" / "add"), read
    /// before the iterable is touched, and a TypeError unless callable.
    /// `None` while it is the intrinsic method, which the native seeds
    /// implement; `Some` for a replaced prototype method or a subclass
    /// override, which seed_collection_with_adder calls. The constructors
    /// inserted every element directly, so `class M extends Map { set(k, v)
    /// {...} }` never saw its constructor's entries and a non-callable
    /// `Map.prototype.set` went unnoticed.
    pub(super) fn collection_seed_adder(
        &mut self,
        module: Option<&Ir3Module>,
        collection_id: ObjectId,
        type_tag: &'static str,
    ) -> Result<Option<Value>, InterpreterError> {
        let key = if matches!(type_tag, "Map" | "WeakMap") {
            "set"
        } else {
            "add"
        };
        let adder = self.proxy_aware_get_property(
            module,
            collection_id,
            key,
            Value::Object(collection_id),
            0,
        )?;
        if !adder.is_callable() {
            let shown = self.value_to_string(&adder);
            return Err(self.throw_js_error(
                "TypeError",
                format!(
                    "'{shown}' returned for property '{key}' of object '#<{type_tag}>' is not a function"
                ),
            ));
        }
        let intrinsic =
            Self::collection_prototype_method(type_tag, key).map(Value::BuiltinFunction);
        Ok((intrinsic.as_ref() != Some(&adder)).then_some(adder))
    }

    /// AddEntriesFromIterable (ES2020 23.1.1.2) and the Set / WeakSet loops
    /// with a guest adder: Call(adder, collection, «key, value») for a Map
    /// or WeakMap entry (`pairs`), «element» otherwise, closing the iterator
    /// when that call or the entry's Get is abrupt.
    pub(super) fn seed_collection_with_adder(
        &mut self,
        module: Option<&Ir3Module>,
        collection_id: ObjectId,
        adder: Value,
        pairs: bool,
        iterable: Value,
    ) -> Result<(), InterpreterError> {
        let receiver = Value::Object(collection_id);
        let mut label = Label::Public;
        let mut source = self.collection_seed_source(module, iterable)?;
        while let Some(element) = self.next_collection_seed(module, &mut source)? {
            self.observe_collection_seed_label(&mut label);
            let arguments = if pairs {
                match self.collection_seed_entry(module, &element) {
                    Ok((key, value)) => vec![key, value],
                    Err(error) => return self.close_collection_seed(module, source, error),
                }
            } else {
                vec![element]
            };
            if let Err(error) =
                self.invoke_inline_method_call(module, adder.clone(), receiver.clone(), arguments)
            {
                return self.close_collection_seed(module, source, error);
            }
        }
        self.finish_collection_seed(label)
    }

    pub(super) fn seed_map_entries_from_iterable(
        &mut self,
        module: Option<&Ir3Module>,
        entries_id: ObjectId,
        iterable: Value,
    ) -> Result<(), InterpreterError> {
        let mut label = Label::Public;
        let mut source = self.collection_seed_source(module, iterable)?;
        while let Some(entry) = self.next_collection_seed(module, &mut source)? {
            self.observe_collection_seed_label(&mut label);
            let (key, value) = match self.collection_seed_entry(module, &entry) {
                Ok(pair) => pair,
                Err(error) => return self.close_collection_seed(module, source, error),
            };
            self.observe_collection_seed_label(&mut label);
            let key_str = Self::collection_key_repr(&key);

            // Charged like `map_collection_set`: a raw insert here left the
            // entries (and a duplicate key's replacement growth) out of the
            // running estimate, which only the full re-walk at every
            // microtask checkpoint used to repair.
            self.set_object_property(entries_id, key_str, value)?;
        }

        self.finish_collection_seed(label)
    }

    pub(super) fn seed_set_values_from_iterable(
        &mut self,
        module: Option<&Ir3Module>,
        values_id: ObjectId,
        iterable: Value,
        weak_values_only: bool,
    ) -> Result<(), InterpreterError> {
        let mut label = Label::Public;
        let mut source = self.collection_seed_source(module, iterable)?;
        while let Some(value) = self.next_collection_seed(module, &mut source)? {
            self.observe_collection_seed_label(&mut label);
            // A Set stores the member itself (as `add` does) so iteration can
            // yield it; a WeakSet is not iterable and keeps a presence marker
            // under the key `WeakSet.prototype.add` uses, and a value that
            // cannot be weakly held is a TypeError, as for `add`.
            let (value_str, stored) = if weak_values_only {
                if !self.can_be_held_weakly(&value) {
                    let error = InterpreterError::TypeError {
                        expected: "object WeakSet value".to_string(),
                        got: value.type_name().to_string(),
                    };
                    return self.close_collection_seed(module, source, error);
                }
                (Self::collection_key_repr(&value), Value::Bool(true))
            } else {
                let value = Self::collection_canonical_member(value);
                (Self::collection_key_repr(&value), value)
            };

            let values_index = values_id.0 as usize;

            // Incremental memory accounting (bd-s8u37): the value is inserted
            // only when absent, so account exactly then.
            let will_insert = self
                .heap
                .get(values_index)
                .map(|v| !v.properties.contains_key(&value_str))
                .unwrap_or(false);
            if will_insert {
                let new_bytes = Self::estimate_property_entry_bytes(&value_str, &stored);
                self.apply_memory_component_delta(0, new_bytes)?;
            }
            self.mutate_heap(|heap| {
                if let Some(values_obj) = heap.get_mut(values_index) {
                    if !values_obj.properties.contains_key(&value_str) {
                        values_obj.properties.insert(value_str, stored);
                    }
                }
            });
        }

        self.finish_collection_seed(label)
    }

    /// A WeakMap seed entry's key and value. As for `WeakMap.prototype.set`,
    /// the key is an object, a function keyed by its own-property backing
    /// object, or a symbol outside the global registry; anything else is a
    /// TypeError instead of being skipped.
    pub(super) fn weakmap_seed_entry(
        &mut self,
        module: Option<&Ir3Module>,
        entry: &Value,
    ) -> Result<(WeakMapKey, Value), InterpreterError> {
        let (key, value) = self.collection_seed_entry(module, entry)?;
        let key_id = if key.is_object_like() {
            self.own_property_holder(module, &key, true)?
                .map(|id| WeakMapKey::Object(id.0))
        } else if let Value::Symbol(symbol) = &key
            && self.can_be_held_weakly(&key)
        {
            Some(WeakMapKey::Symbol(symbol.0))
        } else {
            None
        };
        key_id
            .map(|key_id| (key_id, value))
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "object WeakMap key".to_string(),
                got: key.type_name().to_string(),
            })
    }

    pub(super) fn seed_weakmap_from_iterable(
        &mut self,
        module: Option<&Ir3Module>,
        weakmap_id: ObjectId,
        iterable: Value,
    ) -> Result<(), InterpreterError> {
        let mut updates = BTreeMap::new();
        let mut label = Label::Public;
        let mut source = self.collection_seed_source(module, iterable)?;
        while let Some(entry) = self.next_collection_seed(module, &mut source)? {
            self.observe_collection_seed_label(&mut label);
            match self.weakmap_seed_entry(module, &entry) {
                Ok((key_id, value)) => {
                    updates.insert(key_id, value);
                }
                Err(error) => return self.close_collection_seed(module, source, error),
            }
            self.observe_collection_seed_label(&mut label);
        }

        let Some(storage) = self.weakmap_storage.get(&weakmap_id) else {
            return Ok(());
        };
        let previous_bytes = Self::saturating_sum(updates.keys().filter_map(|key| {
            match *key {
                WeakMapKey::Object(id) => storage.get(id),
                WeakMapKey::Symbol(symbol) => storage.get_symbol(symbol),
            }
            .map(|previous| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_mul(2)
                    .saturating_add(Self::estimate_value_bytes(previous))
            })
        }));
        let next_bytes = Self::saturating_sum(updates.values().map(|value| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_mul(2)
                .saturating_add(Self::estimate_value_bytes(value))
        }));
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.before_seed_surface_write();
        let storage = self
            .weakmap_storage
            .get_mut(&weakmap_id)
            .expect("WeakMap storage was validated before aggregate preflight");
        for (key, value) in updates {
            match key {
                WeakMapKey::Object(id) => storage.set(id, value),
                WeakMapKey::Symbol(symbol) => storage.set_symbol(symbol, value),
            }
        }

        self.finish_collection_seed(label)
    }

    pub(super) fn validate_weakmap_receiver(
        &self,
        receiver: Value,
    ) -> Result<ObjectId, InterpreterError> {
        let weakmap_id = match receiver {
            Value::Object(object_id) => object_id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "WeakMap".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };

        // Validate that this is actually a WeakMap object
        let weakmap_obj = self
            .heap
            .get(weakmap_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: weakmap_id.0 })?;

        if weakmap_obj.brand() != Some("WeakMap") {
            return Err(InterpreterError::TypeError {
                expected: "WeakMap".to_string(),
                got: "object".to_string(),
            });
        }

        // Ensure we have storage for this WeakMap
        if !self.weakmap_storage.contains_key(&weakmap_id) {
            return Err(InterpreterError::TypeError {
                expected: "WeakMap".to_string(),
                got: "uninitialized WeakMap".to_string(),
            });
        }

        Ok(weakmap_id)
    }

    #[allow(dead_code)]
    pub(super) fn weakmap_entries_id(&self, receiver: Value) -> Result<ObjectId, InterpreterError> {
        let weakmap_id = match receiver {
            Value::Object(object_id) => object_id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "WeakMap".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };

        let weakmap_obj = self
            .heap
            .get(weakmap_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: weakmap_id.0 })?;

        if weakmap_obj.brand() != Some("WeakMap") {
            return Err(InterpreterError::TypeError {
                expected: "WeakMap".to_string(),
                got: "object".to_string(),
            });
        }

        match weakmap_obj.properties.get("__entries") {
            Some(Value::Object(entries_id)) => Ok(*entries_id),
            Some(other) => Err(InterpreterError::TypeError {
                expected: "WeakMap entries".to_string(),
                got: other.type_name().to_string(),
            }),
            None => Err(InterpreterError::TypeError {
                expected: "WeakMap entries".to_string(),
                got: "missing".to_string(),
            }),
        }
    }

    /// Unified Number.prototype.toString implementation with bounded radix handling.
    pub(super) fn number_to_string_impl(
        &self,
        number_val: f64,
        radix: i32,
    ) -> Result<String, InterpreterError> {
        // Validate radix according to ECMAScript's accepted range (2-36).
        if radix < 2 || radix > 36 {
            return Err(InterpreterError::RangeError {
                message: format!("toString() radix must be between 2 and 36 (got {radix})"),
            });
        }

        // Handle special values
        if number_val.is_nan() {
            return Ok("NaN".to_string());
        }
        if number_val.is_infinite() {
            return Ok(if number_val.is_sign_positive() {
                "Infinity"
            } else {
                "-Infinity"
            }
            .to_string());
        }

        // Radix 10 is ES2020 7.1.12.1 Number::toString, the same form as
        // `String(x)`: exponent notation outside [1e-6, 1e21), so
        // `(1e21).toString()` is "1e+21" (Rust's `f64` Display printed every
        // digit).
        if radix == 10 {
            return Ok(self.value_to_string(&js_number_to_value(number_val)));
        }

        // This runtime intentionally keeps non-decimal conversion bounded and
        // deterministic while preserving fractional information.
        let mut result = String::new();
        let abs_value = number_val.abs();
        let mut num = abs_value.trunc() as u64;
        let radix_u64 = radix as u64;

        if num == 0 {
            result.push('0');
        } else {
            while num > 0 {
                let digit = (num % radix_u64) as u8;
                let ch = if digit < 10 {
                    (b'0' + digit) as char
                } else {
                    (b'a' + (digit - 10)) as char
                };
                result.insert(0, ch);
                num /= radix_u64;
            }
        }

        let mut fractional = abs_value.fract();
        if fractional > 0.0 {
            result.push('.');
            for _ in 0..64 {
                fractional *= radix as f64;
                let digit = fractional.trunc() as u8;
                let ch = if digit < 10 {
                    (b'0' + digit) as char
                } else {
                    (b'a' + (digit - 10)) as char
                };
                result.push(ch);
                fractional -= f64::from(digit);
                if fractional == 0.0 {
                    break;
                }
            }
            while result.ends_with('0') {
                result.pop();
            }
            if result.ends_with('.') {
                result.pop();
            }
        }

        if number_val.is_sign_negative() && number_val != 0.0 {
            result.insert(0, '-');
        }

        Ok(result)
    }

    /// Map a function index to a builtin capability string if it corresponds to a builtin.
    /// This is a temporary bridge until we have proper builtin registry integration.
    pub(super) fn map_function_index_to_builtin_capability(&self, func_idx: u32) -> Option<String> {
        // Based on the stdlib installation order, map function indices to builtin capabilities
        // This is a simplified mapping for common builtin methods
        // Note: This approach assumes stdlib is installed starting from index 0
        match func_idx {
            // Object methods (installed first in stdlib.rs)
            0 => Some("builtin:ObjectKeys".to_string()),
            1 => Some("builtin:ObjectValues".to_string()),
            2 => Some("builtin:ObjectEntries".to_string()),
            3 => Some("builtin:ObjectAssign".to_string()),
            4 => Some("builtin:ObjectFreeze".to_string()),
            5 => Some("builtin:ObjectCreate".to_string()),

            // Array methods (installed after Object in stdlib.rs)
            10 => Some("builtin:ArrayIsArray".to_string()),
            11 => Some("builtin:ArrayFrom".to_string()),
            12 => Some("builtin:ArrayOf".to_string()),
            13 => Some("builtin:ArrayPrototypePush".to_string()),
            14 => Some("builtin:ArrayPrototypePop".to_string()),
            15 => Some("builtin:ArrayPrototypeShift".to_string()),
            16 => Some("builtin:ArrayPrototypeUnshift".to_string()),
            17 => Some("builtin:ArrayPrototypeJoin".to_string()),
            18 => Some("builtin:ArrayPrototypeIncludes".to_string()),
            19 => Some("builtin:ArrayPrototypeIndexOf".to_string()),
            20 => Some("builtin:ArrayPrototypeSlice".to_string()),

            // String methods
            30 => Some("builtin:StringPrototypeCharAt".to_string()),
            31 => Some("builtin:StringPrototypeIndexOf".to_string()),
            32 => Some("builtin:StringPrototypeSubstring".to_string()),
            33 => Some("builtin:StringPrototypeSlice".to_string()),
            34 => Some("builtin:StringPrototypeToLowerCase".to_string()),
            35 => Some("builtin:StringPrototypeToUpperCase".to_string()),
            36 => Some("builtin:StringPrototypeSplit".to_string()),
            37 => Some("builtin:StringPrototypeTrim".to_string()),

            // Math methods
            50 => Some("builtin:MathAbs".to_string()),
            51 => Some("builtin:MathCeil".to_string()),
            52 => Some("builtin:MathFloor".to_string()),
            53 => Some("builtin:MathRound".to_string()),
            54 => Some("builtin:MathMax".to_string()),
            55 => Some("builtin:MathMin".to_string()),
            56 => Some("builtin:MathRandom".to_string()),

            // JSON methods
            70 => Some("builtin:JsonParse".to_string()),
            71 => Some("builtin:JsonStringify".to_string()),

            // Global functions
            80 => Some("builtin:isNaN".to_string()),
            81 => Some("builtin:isFinite".to_string()),
            82 => Some("builtin:parseInt".to_string()),
            83 => Some("builtin:parseFloat".to_string()),

            // Number methods
            90 => Some("builtin:NumberIsNaN".to_string()),
            91 => Some("builtin:NumberIsFinite".to_string()),

            // Console methods
            100 => Some("builtin:ConsoleLog".to_string()),
            101 => Some("builtin:ConsoleError".to_string()),
            102 => Some("builtin:ConsoleWarn".to_string()),

            // Date methods
            110 => Some("builtin:DateNow".to_string()),
            111 => Some("builtin:Date".to_string()),

            // Additional Math methods
            57 => Some("builtin:MathPow".to_string()),
            58 => Some("builtin:MathSqrt".to_string()),
            59 => Some("builtin:MathSin".to_string()),
            60 => Some("builtin:MathCos".to_string()),
            61 => Some("builtin:MathLog".to_string()),
            62 => Some("builtin:MathExp".to_string()),
            63 => Some("builtin:MathTan".to_string()),
            64 => Some("builtin:MathPI".to_string()),
            65 => Some("builtin:MathTrunc".to_string()),
            66 => Some("builtin:MathSign".to_string()),

            // Additional String methods
            38 => Some("builtin:StringPrototypeIncludes".to_string()),
            39 => Some("builtin:StringPrototypeStartsWith".to_string()),
            40 => Some("builtin:StringPrototypeEndsWith".to_string()),
            41 => Some("builtin:StringPrototypeReplace".to_string()),
            42 => Some("builtin:StringPrototypeRepeat".to_string()),
            43 => Some("builtin:StringPrototypePadStart".to_string()),
            44 => Some("builtin:StringPrototypePadEnd".to_string()),

            // Additional Array methods
            21 => Some("builtin:ArrayPrototypeReverse".to_string()),
            22 => Some("builtin:ArrayPrototypeForEach".to_string()),
            23 => Some("builtin:ArrayPrototypeMap".to_string()),
            24 => Some("builtin:ArrayPrototypeFilter".to_string()),
            25 => Some("builtin:ArrayPrototypeFind".to_string()),
            26 => Some("builtin:ArrayPrototypeConcat".to_string()),
            27 => Some("builtin:ArrayPrototypeReduce".to_string()),
            28 => Some("builtin:ArrayPrototypeSort".to_string()),
            29 => Some("builtin:ArrayPrototypeSplice".to_string()),
            202 => Some("builtin:ArrayPrototypeFlat".to_string()),
            203 => Some("builtin:ArrayPrototypeSome".to_string()),
            204 => Some("builtin:ArrayPrototypeEvery".to_string()),

            // Additional String methods (continued)
            45 => Some("builtin:StringPrototypeMatch".to_string()),
            46 => Some("builtin:StringPrototypeSearch".to_string()),

            // Promise methods
            120 => Some("builtin:PromiseResolve".to_string()),

            // Additional Object methods
            6 => Some("builtin:ObjectHasOwnProperty".to_string()),
            7 => Some("builtin:ObjectDefineProperty".to_string()),

            // Error constructors
            130 => Some("builtin:Error".to_string()),

            // Type conversion constructors
            140 => Some("builtin:Number".to_string()),
            141 => Some("builtin:Boolean".to_string()),

            // Primitive constructors
            150 => Some("builtin:Symbol".to_string()),

            // Operators
            160 => Some("builtin:typeof".to_string()),

            // Collection constructors
            170 => Some("builtin:Map".to_string()),
            171 => Some("builtin:Set".to_string()),
            172 => Some("builtin:WeakMap".to_string()),
            173 => Some("builtin:WeakSet".to_string()),

            // Collection prototype methods
            174 => Some("builtin:MapPrototypeSet".to_string()),
            175 => Some("builtin:MapPrototypeGet".to_string()),
            176 => Some("builtin:SetPrototypeAdd".to_string()),
            177 => Some("builtin:SetPrototypeHas".to_string()),
            178 => Some("builtin:MapPrototypeHas".to_string()),
            179 => Some("builtin:MapPrototypeDelete".to_string()),
            180 => Some("builtin:SetPrototypeDelete".to_string()),
            181 => Some("builtin:SetPrototypeClear".to_string()),
            182 => Some("builtin:ArrayPrototypeLastIndexOf".to_string()),
            183 => Some("builtin:ArrayPrototypeFindIndex".to_string()),
            184 => Some("builtin:StringPrototypeCharCodeAt".to_string()),
            185 => Some("builtin:StringFromCharCode".to_string()),
            186 => Some("builtin:ObjectGetOwnPropertyNames".to_string()),
            187 => Some("builtin:ObjectGetPrototypeOf".to_string()),
            188 => Some("builtin:PromiseReject".to_string()),
            189 => Some("builtin:MathAtan2".to_string()),
            190 => Some("builtin:FunctionPrototypeCall".to_string()),
            191 => Some("builtin:MathAsin".to_string()),
            192 => Some("builtin:MathAcos".to_string()),
            193 => Some("builtin:RegExp".to_string()),
            194 => Some("builtin:ArrayPrototypeReduceRight".to_string()),
            195 => Some("builtin:StringPrototypeSubstr".to_string()),
            196 => Some("builtin:NumberPrototypeToString".to_string()),
            197 => Some("builtin:PromiseAll".to_string()),
            198 => Some("builtin:FunctionPrototypeApply".to_string()),
            199 => Some("builtin:StringPrototypeLocaleCompare".to_string()),
            200 => Some("builtin:DatePrototypeGetTime".to_string()),
            201 => Some("builtin:DatePrototypeToString".to_string()),
            205 => Some("builtin:ObjectPrototypeValueOf".to_string()),
            206 => Some("builtin:ArrayPrototypeFlatMap".to_string()),
            207 => Some("builtin:MathHypot".to_string()),
            208 => Some("builtin:ArrayPrototypeCopyWithin".to_string()),
            209 => Some("builtin:ArrayPrototypeFill".to_string()),
            210 => Some("builtin:StringPrototypeCodePointAt".to_string()),
            211 => Some("builtin:StringFromCodePoint".to_string()),
            212 => Some("builtin:MathImul".to_string()),
            213 => Some("builtin:ArrayPrototypeAt".to_string()),
            214 => Some("builtin:StringPrototypeAt".to_string()),
            215 => Some("builtin:ObjectGetOwnPropertyDescriptor".to_string()),
            216 => Some("builtin:MathClz32".to_string()),
            217 => Some("builtin:ArrayPrototypeEntries".to_string()),
            218 => Some("builtin:ArrayPrototypeKeys".to_string()),
            219 => Some("builtin:ArrayPrototypeValues".to_string()),
            220 => Some("builtin:ObjectSetPrototypeOf".to_string()),
            221 => Some("builtin:SymbolIterator".to_string()),
            222 => Some("builtin:StringPrototypeNormalize".to_string()),
            223 => Some("builtin:StringPrototypeTrimStart".to_string()),
            224 => Some("builtin:StringPrototypeTrimEnd".to_string()),
            225 => Some("builtin:ArrayPrototypeFind".to_string()),
            226 => Some("builtin:StringPrototypePadStart".to_string()),
            227 => Some("builtin:StringPrototypePadEnd".to_string()),
            228 => Some("builtin:ObjectPrototypeHasOwnProperty".to_string()),
            229 => Some("builtin:StringPrototypeStartsWith".to_string()),
            230 => Some("builtin:StringPrototypeEndsWith".to_string()),
            231 => Some("builtin:NumberIsInteger".to_string()),
            232 => Some("builtin:NumberParseFloat".to_string()),
            233 => Some("builtin:StringPrototypeRepeat".to_string()),
            234 => Some("builtin:NumberParseInt".to_string()),
            235 => Some("builtin:StringPrototypeReplace".to_string()),
            236 => Some("builtin:ArrayPrototypeFilter".to_string()),
            237 => Some("builtin:ArrayPrototypeMap".to_string()),
            238 => Some("builtin:StringPrototypeIncludes".to_string()),
            239 => Some("builtin:NumberIsNaN".to_string()),
            240 => Some("builtin:MathPow".to_string()),
            241 => Some("builtin:ArrayPrototypeReduce".to_string()),
            242 => Some("builtin:StringPrototypeMatch".to_string()),
            243 => Some("builtin:ArrayPrototypeReverse".to_string()),
            244 => Some("builtin:MathSin".to_string()),
            245 => Some("builtin:MathCos".to_string()),
            246 => Some("builtin:ArrayPrototypeConcat".to_string()),
            247 => Some("builtin:MathTan".to_string()),
            248 => Some("builtin:ArrayPrototypeSort".to_string()),
            249 => Some("builtin:StringPrototypeMatch".to_string()),
            250 => Some("builtin:MathAtan".to_string()),
            251 => Some("builtin:ArrayPrototypeFill".to_string()),
            252 => Some("builtin:ObjectPrototypePropertyIsEnumerable".to_string()),
            253 => Some("builtin:StringPrototypeConcat".to_string()),
            254 => Some("builtin:MathAtan2".to_string()),
            255 => Some("builtin:ArrayPrototypeEvery".to_string()),
            256 => Some("builtin:DatePrototypeGetTime".to_string()),
            257 => Some("builtin:StringPrototypeLocaleCompare".to_string()),
            258 => Some("builtin:MathLog10".to_string()),
            259 => Some("builtin:ArrayPrototypeSome".to_string()),
            260 => Some("builtin:ObjectPrototypeValueOf".to_string()),
            261 => Some("builtin:StringPrototypeCharCodeAt".to_string()),
            262 => Some("builtin:MathLog2".to_string()),
            263 => Some("builtin:ArrayPrototypeReduceRight".to_string()),
            264 => Some("builtin:ObjectPrototypeToString".to_string()),
            265 => Some("builtin:StringFromCharCode".to_string()),
            266 => Some("builtin:MathAcos".to_string()),
            267 => Some("builtin:ArrayPrototypeLastIndexOf".to_string()),
            268 => Some("builtin:RegExpPrototypeTest".to_string()),
            269 => Some("builtin:StringPrototypeCodePointAt".to_string()),
            270 => Some("builtin:MathAsin".to_string()),
            271 => Some("builtin:ArrayPrototypeFindIndex".to_string()),
            272 => Some("builtin:ObjectGetOwnPropertyNames".to_string()),
            273 => Some("builtin:StringPrototypeNormalize".to_string()),
            274 => Some("builtin:MathCbrt".to_string()),
            275 => Some("builtin:ArrayPrototypeFlat".to_string()),
            276 => Some("builtin:PromiseResolve".to_string()),
            277 => Some("builtin:StringPrototypeReplaceAll".to_string()),
            278 => Some("builtin:MathClz32".to_string()),
            279 => Some("builtin:ArrayPrototypeFlatMap".to_string()),
            280 => Some("builtin:ObjectDefineProperty".to_string()),
            281 => Some("builtin:StringPrototypeAt".to_string()),
            282 => Some("builtin:MathFround".to_string()),
            283 => Some("builtin:ArrayPrototypeAt".to_string()),
            284 => Some("builtin:ObjectGetPrototypeOf".to_string()),
            285 => Some("builtin:StringPrototypeToWellFormed".to_string()),
            286 => Some("builtin:MathAcosh".to_string()),
            287 => Some("builtin:ArrayFromAsync".to_string()),
            288 => Some("builtin:ObjectIs".to_string()),
            289 => Some("builtin:StringPrototypeIsWellFormed".to_string()),
            290 => Some("builtin:MathAsinh".to_string()),
            291 => Some("builtin:ArrayPrototypeWith".to_string()),
            292 => Some("builtin:ObjectSetPrototypeOf".to_string()),
            293 => Some("builtin:StringPrototypeToLowerCase".to_string()),
            294 => Some("builtin:MathAtanh".to_string()),
            295 => Some("builtin:ArrayPrototypeToReversed".to_string()),
            296 => Some("builtin:ObjectHasOwnProperty".to_string()),
            297 => Some("builtin:StringPrototypeToUpperCase".to_string()),
            298 => Some("builtin:MathHypot".to_string()),
            299 => Some("builtin:ArrayPrototypeToSorted".to_string()),
            300 => Some("builtin:ObjectPropertyIsEnumerable".to_string()),
            301 => Some("builtin:StringPrototypeTrimStart".to_string()),
            302 => Some("builtin:MathImul".to_string()),
            303 => Some("builtin:ArrayPrototypeToSpliced".to_string()),
            304 => Some("builtin:ObjectIsExtensible".to_string()),
            305 => Some("builtin:StringPrototypeTrimEnd".to_string()),
            306 => Some("builtin:MathSign".to_string()),
            307 => Some("builtin:ArrayPrototypeGroup".to_string()),
            308 => Some("builtin:ObjectPreventExtensions".to_string()),
            309 => Some("builtin:StringPrototypeSearch".to_string()),
            310 => Some("builtin:MathTrunc".to_string()),
            311 => Some("builtin:ArrayPrototypeGroupToMap".to_string()),
            312 => Some("builtin:ObjectSeal".to_string()),
            313 => Some("builtin:StringPrototypeSubstr".to_string()),
            314 => Some("builtin:NumberPrototypeToFixed".to_string()),
            315 => Some("builtin:ArrayPrototypeCopyWithin".to_string()),
            316 => Some("builtin:ObjectIsFrozen".to_string()),
            317 => Some("builtin:StringPrototypeAnchor".to_string()),
            318 => Some("builtin:NumberPrototypeToExponential".to_string()),
            319 => Some("builtin:ArrayPrototypeValues".to_string()),
            320 => Some("builtin:ObjectIsSealed".to_string()),
            321 => Some("builtin:StringPrototypeBig".to_string()),
            322 => Some("builtin:NumberPrototypeToPrecision".to_string()),
            323 => Some("builtin:ArrayPrototypeKeys".to_string()),
            324 => Some("builtin:WeakMapPrototypeHas".to_string()),
            325 => Some("builtin:StringPrototypeBlink".to_string()),
            326 => Some("builtin:NumberPrototypeValueOf".to_string()),
            327 => Some("builtin:ArrayPrototypeEntries".to_string()),
            328 => Some("builtin:WeakMapPrototypeGet".to_string()),
            329 => Some("builtin:ArrayPrototypeReverse".to_string()),
            330 => Some("builtin:StringPrototypeToLowerCase".to_string()),
            331 => Some("builtin:StringPrototypeToUpperCase".to_string()),
            332 => Some("builtin:ObjectPrototypeToString".to_string()),
            333 => Some("builtin:StringPrototypeTrim".to_string()),
            334 => Some("builtin:ArrayPrototypeForEach".to_string()),
            335 => Some("builtin:NumberIsInteger".to_string()),
            336 => Some("builtin:StringPrototypeEndsWith".to_string()),
            337 => Some("builtin:NumberIsNaN".to_string()),
            338 => Some("builtin:NumberIsFinite".to_string()),
            339 => Some("builtin:StringPrototypeCharAt".to_string()),
            340 => Some("builtin:ArrayPrototypeSome".to_string()),
            341 => Some("builtin:ArrayPrototypeEvery".to_string()),
            342 => Some("builtin:StringPrototypeCharCodeAt".to_string()),
            343 => Some("builtin:NumberPrototypeToString".to_string()),
            344 => Some("builtin:ObjectPrototypeHasOwnProperty".to_string()),
            345 => Some("builtin:StringPrototypeSubstring".to_string()),
            346 => Some("builtin:ArrayPrototypeReduce".to_string()),
            347 => Some("builtin:MathAbs".to_string()),
            348 => Some("builtin:ObjectGetOwnPropertyNames".to_string()),
            349 => Some("builtin:MathMax".to_string()),
            350 => Some("builtin:MathMin".to_string()),
            351 => Some("builtin:StringPrototypeLocaleCompare".to_string()),
            352 => Some("builtin:ArrayPrototypeFilter".to_string()),
            353 => Some("builtin:MathFloor".to_string()),
            354 => Some("builtin:MathCeil".to_string()),
            355 => Some("builtin:MathRound".to_string()),
            // 356: Removed duplicate StringPrototypeSplit mapping (use ID 36 instead)
            357 => Some("builtin:ArrayPrototypeMap".to_string()),
            358 => Some("builtin:MathSqrt".to_string()),
            359 => Some("builtin:MathPow".to_string()),
            360 => Some("builtin:StringPrototypeReplace".to_string()),
            361 => Some("builtin:MathRandom".to_string()),
            362 => Some("builtin:DateNow".to_string()),
            363 => Some("builtin:ArrayPrototypeConcat".to_string()),
            364 => Some("builtin:StringPrototypeMatch".to_string()),
            365 => Some("builtin:JSONStringify".to_string()),
            366 => Some("builtin:JSONParse".to_string()),
            367 => Some("builtin:ArrayPrototypeFind".to_string()),
            368 => Some("builtin:ArrayPrototypeFindIndex".to_string()),
            369 => Some("builtin:MathSin".to_string()),
            370 => Some("builtin:MathCos".to_string()),
            371 => Some("builtin:MathTan".to_string()),
            372 => Some("builtin:RegExpPrototypeTest".to_string()),
            373 => Some("builtin:EncodeURIComponent".to_string()),
            374 => Some("builtin:DecodeURIComponent".to_string()),
            375 => Some("builtin:SetTimeout".to_string()),
            376 => Some("builtin:ClearTimeout".to_string()),
            377 => Some("builtin:parseInt".to_string()),
            378 => Some("builtin:ParseFloat".to_string()),
            379 => Some("builtin:IsNaN".to_string()),
            380 => Some("builtin:IsFinite".to_string()),
            // 381-383: Removed duplicate console mappings (use 100-102 instead)
            384 => Some("builtin:ConsoleInfo".to_string()),
            385 => Some("builtin:ArrayPrototypeSort".to_string()),
            386 => Some("builtin:StringPrototypeToLocaleLowerCase".to_string()),
            387 => Some("builtin:StringPrototypeToLocaleUpperCase".to_string()),
            388 => Some("builtin:MathLog".to_string()),
            389 => Some("builtin:Proxy".to_string()),
            390 => Some("builtin:ProxyRevocable".to_string()),
            391 => Some("builtin:ReflectGet".to_string()),
            392 => Some("builtin:ReflectSet".to_string()),
            393 => Some("builtin:ReflectHas".to_string()),
            394 => Some("builtin:ReflectDeleteProperty".to_string()),
            395 => Some("builtin:ReflectApply".to_string()),
            396 => Some("builtin:ReflectConstruct".to_string()),

            _ => None, // Not a recognized builtin
        }
    }

    #[cfg(test)]
    pub(super) fn builtin_name_from_id(&self, func_idx: u32) -> Option<String> {
        self.map_function_index_to_builtin_capability(func_idx)
    }

    #[cfg(test)]
    pub(super) fn call_builtin_by_id(
        &mut self,
        func_idx: u32,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let Some(capability) = self.map_function_index_to_builtin_capability(func_idx) else {
            return Ok(Value::Undefined);
        };
        self.dispatch_builtin_hostcall(&capability, args, None)
    }

    /// Test-only infallible seed-safe register write. Legacy in-source tests
    /// assigned registers directly via `core.registers[i] = v`; `registers` is
    /// now a `SeedTrackedField<Vec<Value>>` with no `DerefMut`, so writes must
    /// route through `mutate_registers` (which runs `before_seed_surface_write`
    /// to preserve lazy-seed materialization for replay). This helper ports the
    /// legacy assignment pattern without `.expect` noise and grows the register
    /// file if the index is past the current length.
    #[cfg(test)]
    pub(super) fn set_reg(&mut self, idx: usize, value: Value) {
        let previous_bytes = self
            .registers
            .get(idx)
            .map_or(0, Self::estimate_value_bytes);
        let new_bytes = Self::estimate_value_bytes(&value);
        self.note_register_written(idx);
        self.mutate_registers_by_bytes(previous_bytes, new_bytes, |r| {
            if idx >= r.len() {
                r.resize(idx + 1, Value::Undefined);
            }
            r[idx] = value;
        });
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(new_bytes);
    }

    /// Test-only heap-object placement. Legacy in-source tests seeded specific
    /// `ObjectId` slots directly via `interpreter.heap.insert(id, obj)`
    /// (map-style, on a heap that used to be pre-populated) or `heap.push(obj)`
    /// assuming a fixed starting length. `heap` is now a
    /// `SeedTrackedField<Heap>` that starts empty with no `DerefMut`,
    /// so writes route through `mutate_heap`. This grows the vector with default
    /// objects up to `index` and places `object` at that slot, so
    /// `Value::Object(ObjectId(index))` resolves to it — preserving the legacy
    /// tests' intent of "this object lives at this ObjectId".
    #[cfg(test)]
    pub(super) fn set_heap_object_at(&mut self, index: usize, object: HeapObject) {
        self.mutate_heap(|heap| {
            while index >= heap.len() {
                heap.push(HeapObject::default());
            }
            heap[index] = object;
        });
    }

    /// Test-only delegator. Pre-existing in-source tests still call the
    /// historical `call_builtin(cap, args)` name; the current dispatcher lives
    /// on `dispatch_builtin_hostcall(cap, args, module)`. We forward with
    /// `module = None` to keep those tests compiling.
    #[cfg(test)]
    pub(super) fn call_builtin(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.dispatch_builtin_hostcall(cap, args, None)
    }

    /// Test-only register accessor. Pre-existing in-source tests write to
    /// registers via a `set_register(i, v)` method that no longer exists;
    /// registers are now a public `Vec<Value>` field. Returns `Result` so the
    /// legacy `.expect("operation should succeed for valid inputs")` pattern at call sites keeps compiling.
    #[cfg(test)]
    pub(super) fn set_register(&mut self, reg: u32, value: Value) -> Result<(), InterpreterError> {
        let idx = reg as usize;
        self.note_register_written(idx);
        self.mutate_registers(|r| {
            if idx >= r.len() {
                r.resize(idx + 1, Value::Undefined);
            }
            r[idx] = value;
        });
        Ok(())
    }

    /// Test-only register accessor. Paired with `set_register`. Returns
    /// `Result` to match the legacy `.expect("operation should succeed for valid inputs")` pattern.
    #[cfg(test)]
    pub(super) fn read_register(&self, reg: u32) -> Result<Value, InterpreterError> {
        Ok(self
            .registers
            .get(reg as usize)
            .cloned()
            .unwrap_or(Value::Undefined))
    }

    #[cfg(test)]
    pub(super) fn checked_test_builtin_args(
        start: u32,
        len: usize,
    ) -> Result<RegRange, InterpreterError> {
        let count = u32::try_from(len).map_err(|_| InterpreterError::TypeError {
            expected: "u32-bounded builtin argument count".to_string(),
            got: format!("{len} arguments"),
        })?;
        if count > 0 && start.checked_add(count - 1).is_none() {
            return Err(InterpreterError::TypeError {
                expected: "u32-bounded builtin argument register range".to_string(),
                got: format!("{len} arguments starting at r{start}"),
            });
        }
        Ok(RegRange { start, count })
    }

    #[cfg(test)]
    pub(super) fn checked_test_function_id(
        async_function_count: usize,
    ) -> Result<u32, InterpreterError> {
        let count =
            u32::try_from(async_function_count).map_err(|_| InterpreterError::TypeError {
                expected: "u32-bounded test function id allocation".to_string(),
                got: format!("{async_function_count} async functions"),
            })?;
        count
            .checked_add(TEST_FUNCTION_ID_OFFSET)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "u32-bounded test function id allocation".to_string(),
                got: format!(
                    "{async_function_count} async functions + {TEST_FUNCTION_ID_OFFSET} offset"
                ),
            })
    }

    /// Test-only module runner. Pre-existing tests call
    /// `core.execute_module(&module)` repeatedly on a single core to run
    /// independent modules against freshly-seeded registers. Running on `self`
    /// (rather than a throwaway lane) preserves registers/heap the test seeded
    /// via `set_reg`/`set_register`; clearing the seed bookkeeping first gives
    /// each invocation independent "seed then run" semantics, since the current
    /// engine's seed-tracked re-execution would otherwise restore the initial
    /// register seed captured on the first call.
    #[cfg(test)]
    pub(super) fn execute_module(
        &mut self,
        module: &Ir3Module,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.last_pre_run_seed = None;
        self.last_post_run_epoch = None;
        self.execute(module)
    }

    /// Test-only builtin-call helper. Pre-existing tests call
    /// `core.execute_builtin_call(name, args)` with a vector of argument
    /// values; the production dispatcher reads arguments from registers.
    /// The shim stages arguments into the register file, dispatches, and
    /// returns the result.
    #[cfg(test)]
    pub(super) fn execute_builtin_call(
        &mut self,
        cap: &str,
        args: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        let start = 0u32;
        let args_range = Self::checked_test_builtin_args(start, args.len())?;
        for (i, v) in args.iter().enumerate() {
            let offset = u32::try_from(i).map_err(|_| InterpreterError::TypeError {
                expected: "u32-bounded builtin argument register".to_string(),
                got: format!("argument index {i}"),
            })?;
            let register =
                start
                    .checked_add(offset)
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "u32-bounded builtin argument register".to_string(),
                        got: format!("r{start} + argument index {i}"),
                    })?;
            self.set_register(register, v.clone())?;
        }
        self.dispatch_builtin_hostcall(cap, args_range, None)
    }

    /// Test-only function-table appender. Pre-existing tests call
    /// `core.allocate_function(name, params, body, closure_index, captures)`
    /// to register a function before invoking it; the production path fills
    /// the function table at module construction time. The shim returns a
    /// stable, per-core synthetic index based on the current number of
    /// registered async functions — tests only use the returned value as an
    /// opaque handle for `Value::Function(idx)`.
    #[cfg(test)]
    pub(super) fn allocate_function(
        &mut self,
        _name: &str,
        _params: Vec<String>,
        _body: Vec<Ir3Instruction>,
        _closure_index: u32,
        _captures: std::collections::BTreeMap<String, Value>,
    ) -> u32 {
        // Use async_functions length plus a fixed offset so test-generated IDs
        // don't collide with real production function-table indices.
        Self::checked_test_function_id(self.async_functions.len())
            .expect("test function id allocation must not overflow u32")
    }

    /// Compare two values for equality (used by array methods like lastIndexOf).
    /// Implements JavaScript equality comparison rules.
    pub(super) fn values_equal(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Undefined, Value::Undefined) => true,
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => {
                let a_val = a.inner();
                let b_val = b.inner();
                // Handle NaN case (NaN != NaN in JS)
                if a_val.is_nan() || b_val.is_nan() {
                    false
                } else {
                    a_val == b_val
                }
            }
            (Value::Int(a), Value::Float(b)) => {
                let b_val = b.inner();
                if b_val.is_nan() {
                    false
                } else {
                    (*a as f64) == b_val
                }
            }
            (Value::Float(a), Value::Int(b)) => {
                let a_val = a.inner();
                if a_val.is_nan() {
                    false
                } else {
                    a_val == (*b as f64)
                }
            }
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::BigInt(a), Value::BigInt(b)) => a == b,
            (Value::Symbol(a), Value::Symbol(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a.0 == b.0, // Object identity comparison
            // Functions, promises, generators and iterators compare by
            // identity too, as `===` does (strict_eq_values): `[f].indexOf(f)`
            // was -1 and `[f].includes(f)` false.
            (a, b) if a.is_object_like() && b.is_object_like() => a == b,
            _ => false, // Different types are not equal
        }
    }

    /// Convert a Value to a string representation for console output.
    pub(super) fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::Undefined => "undefined".to_string(),
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::BigInt(n) => n.to_string(),
            // ECMAScript Number::toString (NaN, Infinity, -0 -> "0", exponent
            // form outside [1e-6, 1e21)); see `Float64`'s Display.
            Value::Float(f) => f.to_string(),
            Value::Str(s) => s.to_string(),
            Value::Object(id) => {
                // Error instances stringify as `<name>: <message>`; other
                // objects keep the `[object Object]` tag (bd-8enww.4.5).
                if self.heap.get(id.0 as usize).is_some() {
                    self.object_to_coerced_string(*id)
                } else {
                    format!("[object#{}]", id.0)
                }
            }
            Value::Function(idx) => format!("[Function: fn{}]", idx),
            Value::Closure(idx) => format!("[Function: closure{}]", idx),
            Value::Iterator(idx) => format!("[object Iterator#{}]", idx),
            Value::GeneratorFunction(idx) => format!("[GeneratorFunction: gen{}]", idx),
            Value::Generator(idx) => format!("[object Generator#{}]", idx),
            Value::AsyncFunction(idx) => format!("[AsyncFunction: async{}]", idx),
            Value::AsyncFunctionObject(idx) => format!("[object AsyncFunction#{}]", idx),
            Value::AsyncGeneratorFunction(idx) => {
                format!("[AsyncGeneratorFunction: async_gen{}]", idx)
            }
            Value::AsyncGeneratorObject(idx) => format!("[object AsyncGenerator#{}]", idx),
            Value::Promise(idx) => format!("[object Promise#{}]", idx),
            Value::BuiltinFunction(builtin) => {
                format!("[Function: builtin {}]", builtin.display_name())
            }
            Value::Accessor { .. } => "[object Object]".to_string(),
            Value::Symbol(symbol) => self.symbol_display_string(*symbol),
        }
    }

    /// bd-8enww.4.5 (YTBG-D5): string coercion for a heap object id. Error
    /// instances stringify via Error.prototype.toString semantics (their
    /// `name`/`message` properties); every other object keeps the ordinary
    /// `[object Object]` tag. Shared by all object→string coercion sites
    /// (`value_to_string`, `+` concatenation, template literals) so error
    /// stringification is uniform and deterministic.
    pub(super) fn object_to_coerced_string(&self, id: ObjectId) -> String {
        // A wrapper converts through its prototype's toString/valueOf, which
        // answer the wrapped primitive (bd-9vouw.73).
        if let Some(value) = self.primitive_wrapper_value(id) {
            return self.value_to_string(value);
        }
        // Node Buffers implement a UTF-8 `toString` primitive hint. The net
        // stream corpus exercises that through ordinary `text += chunk`
        // coercion, not an explicit method call (bd-7qwej).
        if let Some(view) = self
            .heap
            .get(id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .filter(|view| view.is_buffer)
            && let Ok(bytes) = self.typed_array_view_bytes(view)
        {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        // Array exotic objects coerce through Array.prototype.toString — the
        // spec join of the elements — not the `[object Array]` object tag
        // (bd-sxh8o.3). Console output, template literals, and `+`
        // concatenation all route through here.
        if self
            .heap
            .get(id.0 as usize)
            .is_some_and(|object| object.is_array)
        {
            let mut active = BTreeSet::new();
            if let Ok(joined) = self.array_join_string(id, ",", &mut active) {
                return joined;
            }
        }
        // Any other typed array converts through %TypedArray%.prototype.toString,
        // i.e. Array.prototype.join of its elements.
        if let Some(view) = self
            .heap
            .get(id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            && let Ok(values) = self.typed_array_values_in_range(view, 0, view.length)
        {
            return values
                .iter()
                .map(|value| self.value_to_string(value))
                .collect::<Vec<_>>()
                .join(",");
        }
        // A RegExp converts through RegExp.prototype.toString.
        if let Some((source, flags)) = self.regexp_source_flags_from_object(id) {
            return Self::regexp_display(&source, &flags);
        }
        // A Date converts through Date.prototype.toString: its
        // @@toPrimitive treats the "default" hint as "string".
        if let Some(time) = self.heap.get(id.0 as usize).and_then(HeapObject::date_time) {
            return date_math::to_date_string(time);
        }
        // Everything else converts through Object.prototype.toString: the
        // builtin or @@toStringTag tag (`'' + new Map()` is "[object Map]").
        self.error_object_to_string(id).unwrap_or_else(|| {
            match self.object_prototype_to_string_value(&Value::Object(id)) {
                Value::Str(text) => text.to_string(),
                _ => "[object Object]".to_string(),
            }
        })
    }

    /// ES2020 23.1.3.13 (join) / 23.1.3.30 (toString) element stringification:
    /// concatenate the elements with `separator`; `undefined`/`null` render as
    /// `""`; nested arrays recurse through their own default (`","`) join.
    /// The interpreter's join stack carries the arrays currently being joined
    /// so a cyclic array renders `""` instead of recursing forever, and depth
    /// is bounded fail-closed at [`ARRAY_JOIN_MAX_DEPTH`] (bd-sxh8o.3,
    /// bd-9vouw.481).
    /// Array.prototype.join with observable element conversion (bd-9vouw.37):
    /// an element object that defines a guest toString / valueOf /
    /// @@toPrimitive converts through ToPrimitive(hint "string") (ES2020
    /// 23.1.3.13 step 7.c ToString). Nested arrays join recursively on the
    /// same join stack, under the depth cap [`Self::array_join_string`] also
    /// applies; every other element keeps its non-observable rendering.
    pub(super) fn array_join_observable(
        &mut self,
        module: &Ir3Module,
        array_id: ObjectId,
        separator: &JsString,
    ) -> Result<JsString, InterpreterError> {
        // The ancestor chain is the interpreter's join stack, not a set owned
        // by one call: an element's guest toString may re-enter here, and a
        // fresh set per entry never saw a cycle (`a.push(a); a.join()`
        // overflowed the call stack; V8 keeps one join stack per isolate,
        // bd-9vouw.481). Every array this join puts on the stack comes off
        // again, however it ends.
        if !self.array_join_stack.insert(array_id.0) {
            return Ok(JsString::from(""));
        }
        let mut nested = Vec::new();
        let joined = self.array_join_observable_frames(module, array_id, separator, &mut nested);
        self.array_join_stack.remove(&array_id.0);
        for frame in &nested {
            self.array_join_stack.remove(&frame.array_id.0);
        }
        joined
    }

    /// The join of [`Self::array_join_observable`] over an explicit stack of
    /// nested arrays, so nesting costs no native stack: `nested` holds the
    /// arrays being joined below `array_id`, each on the join stack.
    pub(super) fn array_join_observable_frames(
        &mut self,
        module: &Ir3Module,
        array_id: ObjectId,
        separator: &JsString,
        nested: &mut Vec<ArrayJoinFrame>,
    ) -> Result<JsString, InterpreterError> {
        let len = self.array_like_length(array_id)?;
        let mut root = ArrayJoinFrame::new(array_id, len);
        let comma = JsString::from(",");
        loop {
            let separator = if nested.is_empty() { separator } else { &comma };
            let frame = nested.last_mut().unwrap_or(&mut root);
            if frame.index == frame.len {
                let Some(done) = nested.pop() else {
                    return Ok(root.output.finish());
                };
                self.array_join_stack.remove(&done.array_id.0);
                nested
                    .last_mut()
                    .unwrap_or(&mut root)
                    .output
                    .push(&done.output.finish());
                continue;
            }
            let (current, index) = (frame.array_id, frame.index);
            frame.index += 1;
            if index > 0 {
                frame.output.push(separator);
            }
            let element = self
                .array_index_get(Some(module), current, index)?
                .unwrap_or(Value::Undefined);
            self.join_element_stored_label(current, index as u64)?;
            self.observe_date_value_label(&element)?;
            let rendered = match element {
                Value::Undefined | Value::Null => JsString::from(""),
                Value::Str(text) => text,
                Value::Object(nested_id)
                    if self
                        .heap
                        .get(nested_id.0 as usize)
                        .is_some_and(|object| object.is_array)
                        && !self.object_has_user_conversion_hook(nested_id) =>
                {
                    // An array already being joined renders "" (the cycle
                    // guard); a nested one is joined as its own frame.
                    if !self.array_join_stack.insert(nested_id.0) {
                        JsString::from("")
                    } else if self.array_join_stack.len() > ARRAY_JOIN_MAX_DEPTH {
                        self.array_join_stack.remove(&nested_id.0);
                        // Deeper nesting fails loudly, as Node does once its
                        // native stack runs out, instead of rendering "".
                        return Err(InterpreterError::StackOverflow {
                            depth: self.array_join_stack.len() + 1,
                            max: ARRAY_JOIN_MAX_DEPTH,
                        });
                    } else {
                        match self.array_like_length(nested_id) {
                            Ok(nested_len) => {
                                nested.push(ArrayJoinFrame::new(nested_id, nested_len));
                                continue;
                            }
                            Err(error) => {
                                self.array_join_stack.remove(&nested_id.0);
                                return Err(error);
                            }
                        }
                    }
                }
                Value::Object(object_id) if self.object_has_user_conversion_hook(object_id) => {
                    match self.coerce_runtime_primitive_with_hint(
                        Some(module),
                        Value::Object(object_id),
                        "string",
                    )? {
                        // ToString of a Symbol (a Symbol wrapper converts to
                        // its symbol, bd-9vouw.239) is a TypeError.
                        Value::Symbol(_) => return Err(Self::symbol_to_string_error()),
                        Value::Str(text) => text,
                        primitive => JsString::from(self.value_to_string(&primitive)),
                    }
                }
                Value::Symbol(_) => {
                    return Err(Self::symbol_to_string_error());
                }
                other => JsString::from(self.value_to_string(&other)),
            };
            nested
                .last_mut()
                .unwrap_or(&mut root)
                .output
                .push(&rendered);
        }
    }

    pub(super) fn array_join_string(
        &self,
        array_id: ObjectId,
        separator: &str,
        active: &mut BTreeSet<u32>,
    ) -> Result<String, InterpreterError> {
        if !active.insert(array_id.0) {
            return Ok(String::new());
        }
        if active.len() > ARRAY_STRING_FALLBACK_MAX_DEPTH {
            active.remove(&array_id.0);
            return Ok(String::new());
        }
        let len = self.array_like_length(array_id)?;
        let mut parts = Vec::with_capacity(len.min(4096));
        for index in 0..len {
            let element = self.array_index_value(array_id, index)?;
            let element = element.unwrap_or(Value::Undefined);
            let rendered = match element {
                Value::Undefined | Value::Null => String::new(),
                Value::Object(nested_id)
                    if self
                        .heap
                        .get(nested_id.0 as usize)
                        .is_some_and(|object| object.is_array) =>
                {
                    self.array_join_string(nested_id, ",", active)?
                }
                other => self.value_to_string(&other),
            };
            parts.push(rendered);
        }
        active.remove(&array_id.0);
        Ok(parts.join(separator))
    }

    /// Returns the Error.prototype.toString rendering of `id` when it is an
    /// Error instance, else `None`. Per ECMAScript §20.5.3.4 the result is
    /// `name`, `message`, or `"<name>: <message>"` depending on which parts are
    /// non-empty (`name` defaults to `"Error"`, `message` to `""`). Detection
    /// walks the prototype chain to the realm's `Error.prototype`, so all
    /// subclasses (TypeError, RangeError, ReferenceError, …) are covered.
    /// Non-string `name`/`message` use the static primitive stringifier, which
    /// never re-enters this path (avoiding pathological self-referential
    /// recursion).
    pub(super) fn error_object_to_string(&self, id: ObjectId) -> Option<String> {
        let error_prototype = *self.builtin_prototypes.get("Error")?;
        if !self
            .prototype_chain_contains(id, error_prototype)
            .unwrap_or(false)
        {
            return None;
        }
        // `name` and `message` are usually inherited from the prototypes.
        let name = match self.chain_data_property(id, "name") {
            None | Some(Value::Undefined) => "Error".to_string(),
            Some(Value::Str(s)) => s.to_string(),
            Some(other) => Self::value_to_primitive_string(other),
        };
        let message = match self.chain_data_property(id, "message") {
            None | Some(Value::Undefined) => String::new(),
            Some(Value::Str(s)) => s.to_string(),
            Some(other) => Self::value_to_primitive_string(other),
        };
        Some(if name.is_empty() {
            message
        } else if message.is_empty() {
            name
        } else {
            format!("{name}: {message}")
        })
    }

    // -- Register access ---------------------------------------------------

    pub(super) fn read_reg(&self, reg: u32) -> Result<Value, InterpreterError> {
        if reg >= self.config.max_registers {
            return self.overflow_argument(reg).map(|(value, _)| value.clone());
        }
        let actual_reg = self.register_base + reg as usize;
        Ok(self
            .registers
            .get(actual_reg)
            .cloned()
            .unwrap_or(Value::Undefined))
    }

    pub(super) fn bigint_literal_construction_peak_bytes(value: &str) -> u64 {
        // The dispatch clone owns a `String` while `Arc<str>` copies the same
        // digits into its ArcInner allocation.
        Self::estimate_string_bytes(value).saturating_mul(2)
    }

    pub(super) fn bigint_add_output_bound_bytes(lhs: &str, rhs: &str) -> u64 {
        let output_len = lhs
            .trim_start_matches('-')
            .len()
            .max(rhs.trim_start_matches('-').len())
            .saturating_add(2);
        MEMORY_ESTIMATE_STRING_BASE_BYTES
            .saturating_add(u64::try_from(output_len).unwrap_or(u64::MAX))
    }

    pub(super) fn bigint_add_construction_peak_bytes(lhs: &str, rhs: &str) -> u64 {
        // Unsigned arithmetic transfers its Vec into a String. A negative
        // result may instead overlap that String with sign formatting; Arc
        // conversion later overlaps only the final String. At no point are
        // three result-sized buffers live together.
        Self::bigint_add_output_bound_bytes(lhs, rhs).saturating_mul(2)
    }

    pub(super) fn preflight_register_write_bytes(
        &self,
        reg: u32,
        new_value_bytes: u64,
        explicit_label: Option<&Label>,
    ) -> Result<(), InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + reg as usize;
        let previous_value_bytes = self
            .registers
            .get(actual_reg)
            .map(Self::estimate_value_bytes)
            .unwrap_or(0);
        let previous_label = self.register_labels.get(actual_reg);
        let previous_label_bytes = previous_label.map(Self::estimate_label_bytes).unwrap_or(0);
        let next_label = match explicit_label {
            Some(label) => Some(
                self.active_execution_context_label()
                    .filter(|context| *context > label)
                    .unwrap_or(label),
            ),
            None => self
                .active_execution_context_label()
                .filter(|context| previous_label.is_none_or(|current| *context > current))
                .or(previous_label),
        };
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_value_bytes)
            .saturating_sub(previous_label_bytes)
            .saturating_add(new_value_bytes)
            .saturating_add(next_label.map(Self::estimate_label_bytes).unwrap_or(0));
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        Ok(())
    }

    pub(super) fn preflight_bigint_literal_write(
        &self,
        dst: u32,
        value: &str,
    ) -> Result<(), InterpreterError> {
        self.preflight_register_write_bytes(dst, Self::estimate_string_bytes(value), None)?;
        let actual_reg = self.register_base + dst as usize;
        let previous_label = self.register_labels.get(actual_reg);
        let context_label_bytes = self
            .active_execution_context_label()
            .filter(|context| previous_label.is_none_or(|current| *context > current))
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        self.check_temporary_memory_budget(
            Self::bigint_literal_construction_peak_bytes(value).saturating_add(context_label_bytes),
        )
    }

    pub(super) fn preflight_bigint_add(
        &self,
        dst: u32,
        lhs: u32,
        rhs: u32,
    ) -> Result<Option<u64>, InterpreterError> {
        let left = self.read_reg(lhs)?;
        let right = self.read_reg(rhs)?;
        let (Value::BigInt(left), Value::BigInt(right)) = (&left, &right) else {
            return Ok(None);
        };
        let lhs_label = self.get_register_label(lhs)?;
        let rhs_label = self.get_register_label(rhs)?;
        let winner = if lhs_label >= rhs_label {
            lhs_label
        } else {
            rhs_label
        };
        let peak = Self::bigint_add_construction_peak_bytes(left, right);
        self.preflight_register_write_bytes(
            dst,
            Self::bigint_add_output_bound_bytes(left, right),
            Some(winner),
        )?;
        self.check_temporary_memory_budget(
            peak.saturating_add(Self::estimate_label_bytes(winner)),
        )?;
        Ok(Some(peak))
    }

    /// True when replacing an existing register can neither change logical
    /// memory ownership nor inherit an execution-context label. Ordinary call
    /// frames do not by themselves carry a PC-style label; inline callbacks
    /// and HomeObject-bound method frames remain on the accounted path.
    ///
    /// This is deliberately exhaustive over `Value`: adding a value kind
    /// forces its ownership model to be classified before it can enter the
    /// scalar fast path. Dynamic strings, BigInts, builtins, accessors, and
    /// custom IFC labels retain the fully accounted path below.
    #[inline(always)]
    pub(super) fn static_register_value(value: &Value) -> bool {
        match value {
            Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Object(_)
            | Value::Function(_)
            | Value::Closure(_)
            | Value::Iterator(_)
            | Value::GeneratorFunction(_)
            | Value::Generator(_)
            | Value::AsyncFunction(_)
            | Value::AsyncFunctionObject(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::AsyncGeneratorObject(_)
            | Value::Promise(_)
            | Value::Symbol(_) => true,
            Value::BigInt(_)
            | Value::Str(_)
            | Value::BuiltinFunction(_)
            | Value::Accessor { .. } => false,
        }
    }

    #[inline(always)]
    pub(super) fn static_register_label(label: &Label) -> bool {
        match label {
            Label::Public
            | Label::Internal
            | Label::Confidential
            | Label::Secret
            | Label::TopSecret => true,
            Label::Custom { .. } => false,
        }
    }

    #[inline(always)]
    pub(super) fn static_register_write_eligible(
        &self,
        actual_reg: usize,
        value: &Value,
        next_label: &Label,
    ) -> bool {
        let existing_label_static = if self.all_register_labels_public {
            actual_reg < self.register_labels.len()
        } else {
            self.register_labels
                .get(actual_reg)
                .is_some_and(Self::static_register_label)
        };
        self.active_execution_context_label().is_none()
            && self
                .registers
                .get(actual_reg)
                .is_some_and(Self::static_register_value)
            && existing_label_static
            && Self::static_register_value(value)
            && Self::static_register_label(next_label)
            && !self.memory_request_exceeds_budget(
                self.estimated_memory_bytes,
                self.config.max_total_memory_bytes,
            )
    }

    #[inline]
    pub(super) fn write_reg(&mut self, reg: u32, value: Value) -> Result<(), InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + reg as usize;
        if !self.all_register_labels_public
            && (self.seeded_register_labels.is_empty()
                || !self.seeded_register_labels.contains(&actual_reg))
        {
            return self.write_reg_with_label(reg, value, Label::Public);
        }
        let fast_path_eligible = if self.all_register_labels_public {
            self.static_register_write_eligible(actual_reg, &value, &Label::Public)
        } else {
            self.register_labels
                .get(actual_reg)
                .is_some_and(|label| self.static_register_write_eligible(actual_reg, &value, label))
        };
        if fast_path_eligible {
            // Preserve the sole execution-seed mutation chokepoint before the
            // direct replacement. Eligibility proves the value/label logical
            // byte total is unchanged and no context label can dominate.
            self.note_register_written(actual_reg);
            self.mutate_registers_by_bytes(0, 0, |registers| registers[actual_reg] = value);
            return Ok(());
        }
        self.write_reg_accounted(actual_reg, value)
    }

    #[inline]
    pub(super) fn write_reg_accounted(
        &mut self,
        actual_reg: usize,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.note_register_written(actual_reg);
        // bd-31ijt: the previous implementation called sync_estimated_memory_bytes()
        // after every register write, walking the full heap, registers, scope chain,
        // closures, call stack, iterators, and generators each time — turning every
        // hot-path register write into O(live_state) work. Use an incremental delta
        // against the running `estimated_memory_bytes` total instead. The total is
        // still rebuilt by full recompute on the slower paths (heap operations,
        // call setup/teardown, scope mutations) so any drift is bounded by the
        // distance between two non-register mutations.
        let previous_value_bytes = self
            .registers
            .get(actual_reg)
            .map(Self::estimate_value_bytes)
            .unwrap_or(0);
        let previous_label = self.register_labels.get(actual_reg);
        let previous_label_bytes = previous_label.map(Self::estimate_label_bytes).unwrap_or(0);
        let context_dominates = self
            .active_execution_context_label()
            .is_some_and(|context| previous_label.is_none_or(|current| context > current));
        let next_label_bytes = if context_dominates {
            self.active_execution_context_label()
                .map(Self::estimate_label_bytes)
                .unwrap_or(0)
        } else {
            previous_label_bytes
        };
        let new_value_bytes = Self::estimate_value_bytes(&value);
        let projected = self
            .estimated_memory_bytes
            .saturating_sub(previous_value_bytes)
            .saturating_sub(previous_label_bytes)
            .saturating_add(new_value_bytes)
            .saturating_add(next_label_bytes);
        if self.memory_request_exceeds_budget(projected, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(projected, self.heap_object_count_u32()));
        }

        // Refusal above leaves both parallel files and their lengths intact.
        // Resize only after the combined value+effective-label projection fits.
        self.mutate_registers_by_bytes(previous_value_bytes, new_value_bytes, |registers| {
            if actual_reg >= registers.len() {
                let new_len = actual_reg + 1;
                let growth_capacity = new_len + (new_len >> 2);
                registers.reserve(growth_capacity.saturating_sub(registers.capacity()));
                registers.resize(new_len, Value::Undefined);
            }
            registers[actual_reg] = value;
        });
        if actual_reg >= self.register_labels.len() {
            self.register_labels.resize(actual_reg + 1, Label::Public);
        }
        if context_dominates {
            let previous_label =
                std::mem::replace(&mut self.register_labels[actual_reg], Label::Public);
            drop(previous_label);
            let next_label = self
                .active_execution_context_label()
                .expect("dominant inline callback context was checked")
                .clone();
            if !matches!(&next_label, Label::Public) {
                self.all_register_labels_public = false;
            }
            self.register_labels[actual_reg] = next_label;
        }
        self.adjust_register_labels_bytes(previous_label_bytes, next_label_bytes);
        self.estimated_memory_bytes = projected;
        Ok(())
    }

    #[inline]
    pub(super) fn write_reg_with_label(
        &mut self,
        reg: u32,
        value: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + reg as usize;
        if self.static_register_write_eligible(actual_reg, &value, &label) {
            // The existing and replacement value/label pairs own zero dynamic
            // bytes. Keep seed materialization and epoch advancement exact,
            // then replace both parallel register files as one logical write.
            self.note_register_written(actual_reg);
            self.mutate_registers_by_bytes(0, 0, |registers| registers[actual_reg] = value);
            if !(self.all_register_labels_public && matches!(&label, Label::Public)) {
                if !matches!(&label, Label::Public) {
                    self.all_register_labels_public = false;
                }
                self.register_labels[actual_reg] = label;
            }
            return Ok(());
        }
        self.write_reg_with_label_accounted(actual_reg, value, label)
    }

    #[inline]
    pub(super) fn write_reg_with_label_accounted(
        &mut self,
        actual_reg: usize,
        value: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        self.note_register_written(actual_reg);
        let previous_value_bytes = self
            .registers
            .get(actual_reg)
            .map(Self::estimate_value_bytes)
            .unwrap_or(0);
        let previous_label_bytes = self
            .register_labels
            .get(actual_reg)
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let context_dominates = self
            .active_execution_context_label()
            .is_some_and(|context| context > &label);
        let next_label_bytes = if context_dominates {
            self.active_execution_context_label()
                .map(Self::estimate_label_bytes)
                .unwrap_or(0)
        } else {
            Self::estimate_label_bytes(&label)
        };
        let new_value_bytes = Self::estimate_value_bytes(&value);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_value_bytes)
            .saturating_sub(previous_label_bytes)
            .saturating_add(new_value_bytes)
            .saturating_add(next_label_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }

        self.mutate_registers_by_bytes(previous_value_bytes, new_value_bytes, |registers| {
            if actual_reg >= registers.len() {
                registers.resize(actual_reg + 1, Value::Undefined);
            }
            registers[actual_reg] = value;
        });
        if actual_reg >= self.register_labels.len() {
            self.register_labels.resize(actual_reg + 1, Label::Public);
        }
        let previous_label =
            std::mem::replace(&mut self.register_labels[actual_reg], Label::Public);
        drop(previous_label);
        let next_label = if context_dominates {
            drop(label);
            self.active_execution_context_label()
                .expect("dominant inline callback context was checked")
                .clone()
        } else {
            label
        };
        let is_public = matches!(&next_label, Label::Public);
        self.register_labels[actual_reg] = next_label;
        if !is_public {
            self.all_register_labels_public = false;
        }
        self.adjust_register_labels_bytes(previous_label_bytes, next_label_bytes);
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    /// Advance to and reset one stacked register frame as a value+label unit.
    pub(super) fn enter_stacked_register_frame(
        &mut self,
        compact_tier1: Option<&CompactTier1Program>,
    ) -> Result<(), InterpreterError> {
        let requested_clear_width = compact_tier1
            .and_then(|program| program.function_frame_clear_width(self.config.max_registers))
            .unwrap_or(self.config.max_registers as usize);
        self.enter_stacked_register_frame_width(requested_clear_width)
    }

    /// Advance to one exact verified callee frame: the width the compact plan
    /// verified or, without one, the width `execute` verified for its entry
    /// module (bd-9vouw.72). The shared high-water mark keeps this safe when a
    /// wider function previously occupied the same physical registers.
    pub(super) fn enter_stacked_register_frame_for_function(
        &mut self,
        module: &Ir3Module,
        compact_tier1: Option<&CompactTier1Program>,
        function_index: u32,
    ) -> Result<(), InterpreterError> {
        let max_registers = self.config.max_registers;
        let requested_clear_width = compact_tier1
            .and_then(|program| program.callee_frame_clear_width(function_index, max_registers))
            .or_else(|| self.entry_frame_width(module, function_index))
            .unwrap_or(max_registers as usize);
        self.enter_stacked_register_frame_width(requested_clear_width)
    }

    /// `function_index`'s verified frame width when `module` is the module the
    /// running `execute` call verified (`entry_frame_widths`).
    pub(super) fn entry_frame_width(
        &self,
        module: &Ir3Module,
        function_index: u32,
    ) -> Option<usize> {
        let (address, widths) = self.entry_frame_widths.as_ref()?;
        if *address != Self::module_address(module) {
            return None;
        }
        widths
            .get(function_index as usize)
            .copied()
            .filter(|width| *width > 0 && *width <= self.config.max_registers)
            .map(|width| width as usize)
    }

    /// Open a callee window right above the caller's and reset it
    /// (bd-9vouw.72). `width` must cover every register the new frame can
    /// address: a verified frame width, a trampoline's operand count, or
    /// `max_registers`. Refuses, before changing any state, a window that
    /// would take the register file past `register_file_slot_limit`; the
    /// callee's `CallFrame` is already pushed and charged, so the refusal
    /// leaves the usual state for a stack overflow.
    pub(super) fn enter_stacked_register_frame_width(
        &mut self,
        width: usize,
    ) -> Result<(), InterpreterError> {
        let max_registers = self.config.max_registers as usize;
        let base = self.register_base.saturating_add(self.register_width);
        // Every window is physically `max_registers` long
        // (`clear_current_register_frame_width`), so this bounds the file.
        if base.saturating_add(max_registers)
            > register_file_slot_limit(self.config.max_call_depth, max_registers)
        {
            let depth = self.effective_call_depth();
            return Err(InterpreterError::StackOverflow {
                depth,
                max: depth.saturating_sub(1),
            });
        }
        self.register_base = base;
        self.register_width = width.min(max_registers);
        // The callee's window and whatever an earlier frame or write left
        // past it (bd-9vouw.499); every register past `register_dirty_end`
        // is already clear.
        let window_end = base.saturating_add(self.register_width);
        let clear_end = window_end.max(self.register_dirty_end);
        // The test build checks the invariant a window past the clear: a
        // write that skipped `note_register_written` would show up here.
        #[cfg(test)]
        {
            let check_end = clear_end.saturating_add(max_registers);
            debug_assert!(
                self.registers
                    .get(clear_end..check_end.min(self.registers.len()))
                    .unwrap_or(&[])
                    .iter()
                    .all(|value| matches!(value, Value::Undefined))
                    && self
                        .register_labels
                        .get(clear_end..check_end.min(self.register_labels.len()))
                        .unwrap_or(&[])
                        .iter()
                        .all(|label| matches!(label, Label::Public)),
                "a register past register_dirty_end holds a value (bd-9vouw.499)"
            );
        }
        self.clear_current_register_frame_width(clear_end - base);
        self.register_dirty_end = window_end;
        Ok(())
    }

    /// Reset the active stacked register frame as one value+label unit.
    ///
    /// Values have always been isolated per call frame. Keeping the parallel
    /// label file at the same physical indices prevents a new callee from
    /// inheriting stale caller taint after `register_base` advances.
    #[cfg(test)]
    pub(super) fn clear_current_register_frame(&mut self) {
        self.clear_current_register_frame_width(self.config.max_registers as usize);
    }

    /// End of the live prefix of the register window `start..end`: every
    /// register past it is cleared (undefined with a Public label), the state
    /// `clear_current_register_frame_width` leaves (bd-9vouw.167). A register
    /// without a parallel label counts as live, so a short label file still
    /// fails the caller's own range checks. With complete parallel files,
    /// the dirty bound excludes the already-cleared physical tail.
    pub(super) fn register_window_live_end(&self, start: usize, end: usize) -> usize {
        let live_end =
            if start < end && (end > self.registers.len() || end > self.register_labels.len()) {
                // Missing capacity is observable to the suspension preflight.
                // Do not let the dirty bound hide an invalid parallel file.
                end
            } else {
                (start..end.min(self.register_dirty_end))
                    .rev()
                    .find(|&index| {
                        !matches!(self.registers.get(index), Some(Value::Undefined))
                            || !matches!(self.register_labels.get(index), Some(Label::Public))
                    })
                    .map_or(start, |index| index + 1)
            };
        #[cfg(any(test, debug_assertions))]
        debug_assert_eq!(
            live_end,
            self.register_window_live_end_by_walk(start, end),
            "async register window exceeded its dirty bound (bd-9vouw.500)"
        );
        live_end
    }

    #[cfg(any(test, debug_assertions))]
    pub(super) fn register_window_live_end_by_walk(&self, start: usize, end: usize) -> usize {
        (start..end)
            .rev()
            .find(|&index| {
                !matches!(self.registers.get(index), Some(Value::Undefined))
                    || !matches!(self.register_labels.get(index), Some(Label::Public))
            })
            .map_or(start, |index| index + 1)
    }

    pub(super) fn clear_current_register_frame_width(&mut self, clear_width: usize) {
        let frame_start = self.register_base;
        let frame_end = frame_start + clear_width;
        // Preserve the legacy fixed-stride physical extent even when only a
        // verified active prefix needs repeated clearing. Snapshot preflights
        // deliberately charge Vec length, so shortening the backing vectors
        // would change a later callback's memory-budget refusal boundary.
        let physical_frame_end = frame_start + self.config.max_registers as usize;
        let released_value_bytes = self
            .registers
            .get(frame_start..frame_end.min(self.registers.len()))
            .unwrap_or(&[])
            .iter()
            .fold(0u64, |total, value| {
                total.saturating_add(Self::estimate_value_bytes(value))
            });
        self.mutate_registers_by_bytes(released_value_bytes, 0, |registers| {
            if physical_frame_end > registers.len() {
                registers.resize(physical_frame_end, Value::Undefined);
            }
            // A clear past one window (registers an earlier, deeper frame
            // left, bd-9vouw.499) stops at the file's end. Only a register
            // that holds something is written: `fill` cloned `Undefined` into
            // and dropped every slot of the window on every call
            // (bd-9vouw.504).
            let end = frame_end.min(registers.len());
            for register in &mut registers[frame_start..end] {
                if !matches!(register, Value::Undefined) {
                    *register = Value::Undefined;
                }
            }
        });
        let released_label_bytes = if self.all_register_labels_public {
            0
        } else {
            Self::saturating_sum(
                self.register_labels
                    .get(frame_start..frame_end.min(self.register_labels.len()))
                    .unwrap_or(&[])
                    .iter()
                    .map(Self::estimate_label_bytes),
            )
        };
        if physical_frame_end > self.register_labels.len() {
            self.register_labels
                .resize(physical_frame_end, Label::Public);
        }
        if !self.all_register_labels_public {
            let label_end = frame_end.min(self.register_labels.len());
            for label in &mut self.register_labels[frame_start..label_end] {
                if !matches!(label, Label::Public) {
                    *label = Label::Public;
                }
            }
            self.adjust_register_labels_bytes(released_label_bytes, 0);
        }
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_value_bytes)
            .saturating_sub(released_label_bytes);
    }

    // -- Heap operations ---------------------------------------------------

    /// Roll back transaction-owned heap appends and every index keyed by the
    /// discarded object ids. Keeping this paired prevents stale remembered-set
    /// entries from surviving an otherwise atomic allocation refusal.
    pub(super) fn rollback_heap_to_len(&mut self, previous_heap_len: usize) {
        self.mutate_heap(|heap| heap.truncate(previous_heap_len));
        self.gc_remembered_set
            .retain(|object_id| (object_id.0 as usize) < previous_heap_len);
    }

    /// Undo a refused allocation that materialized intrinsic prototypes on
    /// its way (bd-9vouw.104, bd-9vouw.157): truncate the heap, drop the
    /// registry entries of the prototypes allocated past the checkpoint
    /// (nothing else can hold them yet) and restore the estimate.
    pub(super) fn rollback_heap_and_new_prototypes(
        &mut self,
        previous_heap_len: usize,
        previous_estimated_bytes: u64,
    ) {
        self.rollback_heap_to_len(previous_heap_len);
        if self
            .builtin_prototypes
            .values()
            .any(|id| id.0 as usize >= previous_heap_len)
        {
            self.mutate_builtin_prototypes(|prototypes| {
                prototypes.retain(|_, id| (id.0 as usize) < previous_heap_len);
            });
        }
        self.estimated_memory_bytes = previous_estimated_bytes;
    }

    pub(super) fn estimate_string_bytes(text: &str) -> u64 {
        MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(text.len() as u64)
    }

    pub(super) fn saturating_sum(values: impl Iterator<Item = u64>) -> u64 {
        values.fold(0u64, u64::saturating_add)
    }

    pub(super) fn estimate_js_string_bytes(text: &JsString) -> u64 {
        let malformed_utf16_bytes = if text.is_well_formed() {
            0
        } else {
            MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(
                u64::try_from(text.utf16_len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(2),
            )
        };
        // retained_bytes does not join a concatenation; estimating
        // through &str would (bd-9vouw.468).
        text.retained_bytes(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(malformed_utf16_bytes)
    }

    #[inline]
    pub(super) fn estimate_value_bytes(value: &Value) -> u64 {
        // Keep the overwhelmingly common non-accessor path allocation-free.
        // Only accessor graphs need the iterative worklist/memo machinery
        // (estimate_accessor_value_bytes); constructing it for every
        // integer/object/function property made exact-carrier preflight
        // allocate before its own peak gate. The match is inlined into every
        // register write and frame estimate, which call this several times
        // per instruction (bd-9vouw.497).
        match value {
            Value::BigInt(digits) => Self::estimate_string_bytes(digits),
            Value::Str(text) => Self::estimate_js_string_bytes(text),
            Value::BuiltinFunction(builtin) => {
                Self::estimate_string_bytes(&builtin.module_specifier)
            }
            Value::Accessor { .. } => Self::estimate_accessor_value_bytes(value),
            _ => 0,
        }
    }

    #[inline(never)]
    pub(super) fn estimate_accessor_value_bytes(value: &Value) -> u64 {
        // Accessors form an immutable `Arc<Value>` graph. Walk that graph
        // iteratively so an embedder-supplied chain cannot exhaust the host
        // stack, and memoize each shared node so a compact diamond/DAG cannot
        // make accounting take exponential time. A shared child is still
        // charged once per owning edge below: memoization avoids repeated
        // computation, not the conservative logical-owner charge.
        let arc_value_bytes = u64::try_from(std::mem::size_of::<Value>())
            .unwrap_or(u64::MAX)
            .saturating_add(
                u64::try_from(2usize.saturating_mul(std::mem::size_of::<usize>()))
                    .unwrap_or(u64::MAX),
            );
        let mut memo = BTreeMap::<*const Value, u64>::new();
        let mut stack = vec![(value, None, false)];
        let mut root_estimate = 0u64;

        while let Some((current, key, expanded)) = stack.pop() {
            if key.is_some_and(|key| memo.contains_key(&key)) {
                continue;
            }

            if !expanded && let Value::Accessor { get, set } = current {
                stack.push((current, key, true));
                for nested in [get.as_ref(), set.as_ref()].into_iter().flatten() {
                    let nested_key = Arc::as_ptr(nested);
                    if !memo.contains_key(&nested_key) {
                        stack.push((nested.as_ref(), Some(nested_key), false));
                    }
                }
                continue;
            }

            let estimate = match current {
                Value::BigInt(digits) => Self::estimate_string_bytes(digits),
                Value::Str(text) => Self::estimate_js_string_bytes(text),
                Value::BuiltinFunction(builtin) => {
                    Self::estimate_string_bytes(&builtin.module_specifier)
                }
                Value::Accessor { get, set } => [get, set].into_iter().fold(0u64, |total, slot| {
                    total.saturating_add(slot.as_ref().map_or(0, |nested| {
                        arc_value_bytes.saturating_add(
                            memo.get(&Arc::as_ptr(nested)).copied().unwrap_or(u64::MAX),
                        )
                    }))
                }),
                _ => 0,
            };
            if let Some(key) = key {
                memo.insert(key, estimate);
            } else {
                root_estimate = estimate;
            }
        }

        root_estimate
    }

    /// Allocation-free logical ownership used before admitting a lazy seed.
    /// Accessor graphs are bounded explicitly: an over-deep/cyclic graph is a
    /// deterministic `u64::MAX` refusal rather than native-stack growth or an
    /// unbudgeted worklist allocation.
    pub(super) fn estimate_execution_seed_value_bytes(value: &Value) -> u64 {
        const MAX_ACCESSOR_GRAPH_WORK: usize = 256;

        // Only accessor pairs nest. Every other value is its own total, so it
        // skips zero-filling the 2 KiB work list: the reduce lane sums this over
        // every register on every step.
        match value {
            Value::BigInt(digits) => return Self::estimate_string_bytes(digits),
            Value::Str(text) => return Self::estimate_js_string_bytes(text),
            Value::BuiltinFunction(builtin) => {
                return Self::estimate_string_bytes(&builtin.module_specifier);
            }
            Value::Accessor { .. } => {}
            _ => return 0,
        }
        let arc_value_bytes = u64::try_from(std::mem::size_of::<Value>())
            .unwrap_or(u64::MAX)
            .saturating_add(
                u64::try_from(2usize.saturating_mul(std::mem::size_of::<usize>()))
                    .unwrap_or(u64::MAX),
            );
        let mut work: [Option<&Value>; MAX_ACCESSOR_GRAPH_WORK] = [None; MAX_ACCESSOR_GRAPH_WORK];
        work[0] = Some(value);
        let mut work_len = 1usize;
        let mut visited = 0usize;
        let mut total = 0u64;

        while work_len != 0 {
            work_len -= 1;
            let current = work[work_len]
                .take()
                .expect("execution-seed value work slot is initialized");
            visited = visited.saturating_add(1);
            if visited > MAX_ACCESSOR_GRAPH_WORK {
                return u64::MAX;
            }
            match current {
                Value::BigInt(digits) => {
                    total = total.saturating_add(Self::estimate_string_bytes(digits));
                }
                Value::Str(text) => {
                    total = total.saturating_add(Self::estimate_js_string_bytes(text));
                }
                Value::BuiltinFunction(builtin) => {
                    total = total
                        .saturating_add(Self::estimate_string_bytes(&builtin.module_specifier));
                }
                Value::Accessor { get, set } => {
                    for nested in [get.as_ref(), set.as_ref()].into_iter().flatten() {
                        total = total.saturating_add(arc_value_bytes);
                        if work_len == MAX_ACCESSOR_GRAPH_WORK {
                            return u64::MAX;
                        }
                        work[work_len] = Some(nested.as_ref());
                        work_len += 1;
                    }
                }
                _ => {}
            }
            if total == u64::MAX {
                return total;
            }
        }
        total
    }

    pub(super) fn estimate_execution_seed_ordered_value_map_bytes(
        properties: &OrderedStringMap<Value>,
    ) -> u64 {
        let exact_order_is_active = properties.exact_len() != properties.len();
        Self::saturating_sum(properties.well_formed_data_entries().map(|(key, value)| {
            let owned_key_copies =
                if exact_order_is_active && Self::canonical_array_index_key(key).is_none() {
                    4
                } else {
                    2
                };
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_string_bytes(key).saturating_mul(owned_key_copies))
                .saturating_add(Self::estimate_execution_seed_value_bytes(value))
        }))
        .saturating_add(Self::saturating_sum(
            properties.exact_only_data_entries().map(|(key, value)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_js_string_bytes(key).saturating_mul(3))
                    .saturating_add(Self::estimate_execution_seed_value_bytes(value))
            }),
        ))
        .saturating_add(Self::saturating_sum(
            properties
                .baseline_symbol_properties()
                .map(|(_, property)| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add((std::mem::size_of::<SymbolId>() as u64).saturating_mul(2))
                        .saturating_add(match property {
                            BaselineSymbolProperty::Data(value) => {
                                Self::estimate_execution_seed_value_bytes(value)
                            }
                            BaselineSymbolProperty::Accessor { get, set } => get
                                .as_ref()
                                .map(Self::estimate_execution_seed_value_bytes)
                                .unwrap_or(0)
                                .saturating_add(
                                    set.as_ref()
                                        .map(Self::estimate_execution_seed_value_bytes)
                                        .unwrap_or(0),
                                ),
                        })
                }),
        ))
    }

    pub(super) fn estimate_ordered_property_map_bytes_nonalloc(
        properties: &OrderedStringMap<Value>,
    ) -> u64 {
        Self::estimate_execution_seed_ordered_value_map_bytes(properties)
    }

    pub(super) fn estimate_projected_string_accessor_map_bytes(
        properties: &OrderedStringMap<Value>,
        target: &JsString,
        accessor_bytes: u64,
    ) -> u64 {
        let exact_order_is_active =
            properties.exact_len() != properties.len() || target.as_str().is_none();
        let well_formed = Self::saturating_sum(
            properties
                .well_formed_data_entries()
                .filter(|(key, _)| target.as_str() != Some(key.as_str()))
                .map(|(key, value)| {
                    let owned_key_copies = if exact_order_is_active
                        && Self::canonical_array_index_key(key).is_none()
                    {
                        4
                    } else {
                        2
                    };
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(
                            Self::estimate_string_bytes(key).saturating_mul(owned_key_copies),
                        )
                        .saturating_add(Self::estimate_execution_seed_value_bytes(value))
                }),
        );
        let exact_only = Self::saturating_sum(
            properties
                .exact_only_data_entries()
                .filter(|(key, _)| *key != target)
                .map(|(key, value)| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(Self::estimate_js_string_bytes(key).saturating_mul(3))
                        .saturating_add(Self::estimate_execution_seed_value_bytes(value))
                }),
        );
        let symbols = Self::saturating_sum(properties.baseline_symbol_properties().map(
            |(_, property)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add((std::mem::size_of::<SymbolId>() as u64).saturating_mul(2))
                    .saturating_add(match property {
                        BaselineSymbolProperty::Data(value) => {
                            Self::estimate_execution_seed_value_bytes(value)
                        }
                        BaselineSymbolProperty::Accessor { get, set } => get
                            .as_ref()
                            .map(Self::estimate_execution_seed_value_bytes)
                            .unwrap_or(0)
                            .saturating_add(
                                set.as_ref()
                                    .map(Self::estimate_execution_seed_value_bytes)
                                    .unwrap_or(0),
                            ),
                    })
            },
        ));
        let target_bytes = match target.as_str() {
            Some(key) => {
                let owned_key_copies =
                    if exact_order_is_active && Self::canonical_array_index_key(key).is_none() {
                        4
                    } else {
                        2
                    };
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(
                        Self::estimate_string_bytes(key).saturating_mul(owned_key_copies),
                    )
                    .saturating_add(accessor_bytes)
            }
            None => MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_js_string_bytes(target).saturating_mul(3))
                .saturating_add(accessor_bytes),
        };
        well_formed
            .saturating_add(exact_only)
            .saturating_add(symbols)
            .saturating_add(target_bytes)
    }

    pub(super) fn estimate_projected_symbol_property_map_bytes(
        properties: &OrderedStringMap<Value>,
        target: SymbolId,
        next: &BaselineSymbolProperty<Value>,
    ) -> u64 {
        let previous = properties
            .baseline_symbol_property(core_symbol_id(target))
            .map_or(0, |property| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add((std::mem::size_of::<SymbolId>() as u64).saturating_mul(2))
                    .saturating_add(match property {
                        BaselineSymbolProperty::Data(value) => {
                            Self::estimate_execution_seed_value_bytes(value)
                        }
                        BaselineSymbolProperty::Accessor { get, set } => get
                            .as_ref()
                            .map(Self::estimate_execution_seed_value_bytes)
                            .unwrap_or(0)
                            .saturating_add(
                                set.as_ref()
                                    .map(Self::estimate_execution_seed_value_bytes)
                                    .unwrap_or(0),
                            ),
                    })
            });
        let next = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add((std::mem::size_of::<SymbolId>() as u64).saturating_mul(2))
            .saturating_add(match next {
                BaselineSymbolProperty::Data(value) => {
                    Self::estimate_execution_seed_value_bytes(value)
                }
                BaselineSymbolProperty::Accessor { get, set } => get
                    .as_ref()
                    .map(Self::estimate_execution_seed_value_bytes)
                    .unwrap_or(0)
                    .saturating_add(
                        set.as_ref()
                            .map(Self::estimate_execution_seed_value_bytes)
                            .unwrap_or(0),
                    ),
            });
        Self::estimate_ordered_property_map_bytes_nonalloc(properties)
            .saturating_sub(previous)
            .saturating_add(next)
    }

    pub(super) fn estimate_execution_seed_ordered_label_map_bytes(
        labels: &OrderedStringMap<Label>,
    ) -> u64 {
        let exact_order_is_active = labels.exact_len() != labels.len();
        Self::saturating_sum(labels.well_formed_data_entries().map(|(key, label)| {
            let owned_key_copies =
                if exact_order_is_active && Self::canonical_array_index_key(key).is_none() {
                    4
                } else {
                    2
                };
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_string_bytes(key).saturating_mul(owned_key_copies))
                .saturating_add(Self::estimate_label_bytes(label))
        }))
        .saturating_add(Self::saturating_sum(labels.exact_only_data_entries().map(
            |(key, label)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_js_string_bytes(key).saturating_mul(3))
                    .saturating_add(Self::estimate_label_bytes(label))
            },
        )))
        .saturating_add(Self::saturating_sum(
            labels.baseline_symbol_properties().map(|(_, property)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add((std::mem::size_of::<SymbolId>() as u64).saturating_mul(2))
                    .saturating_add(match property {
                        BaselineSymbolProperty::Data(label) => Self::estimate_label_bytes(label),
                        BaselineSymbolProperty::Accessor { get, set } => get
                            .as_ref()
                            .map(Self::estimate_label_bytes)
                            .unwrap_or(0)
                            .saturating_add(
                                set.as_ref().map(Self::estimate_label_bytes).unwrap_or(0),
                            ),
                    })
            }),
        ))
    }

    pub(super) fn estimate_execution_seed_heap_object_bytes(object: &HeapObject) -> u64 {
        Self::estimate_execution_seed_ordered_value_map_bytes(&object.properties)
            .saturating_add(Self::estimate_execution_seed_ordered_label_map_bytes(
                &object.property_labels,
            ))
            .saturating_add(
                object
                    .date_value
                    .as_ref()
                    .map_or(0, |_| std::mem::size_of::<Float64>() as u64),
            )
            .saturating_add(
                object
                    .collection_storage
                    .as_ref()
                    .map_or(0, |_| std::mem::size_of::<ObjectId>() as u64),
            )
            .saturating_add(
                object
                    .array_buffer
                    .as_ref()
                    .map(|backing| {
                        u64::try_from(backing.bytes.len())
                            .unwrap_or(u64::MAX)
                            .saturating_add(Self::estimate_label_bytes(&backing.label))
                    })
                    .unwrap_or(0),
            )
            .saturating_add(
                object
                    .derived_constructor_parent
                    .as_deref()
                    .map(Self::estimate_execution_seed_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                object
                    .class_fields
                    .as_deref()
                    .map(Self::estimate_execution_seed_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                object
                    .primitive_value
                    .as_deref()
                    .map(Self::estimate_execution_seed_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::saturating_sum(object.private_elements.values().map(
                |element| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(Self::saturating_sum(
                        element
                            .values()
                            .map(Self::estimate_execution_seed_value_bytes),
                    ))
                },
            )))
            .saturating_add(
                object
                    .derived_constructor_parent_label
                    .as_deref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::saturating_sum(
                object
                    .deleted_virtual_keys
                    .iter()
                    .map(Self::estimate_property_attributes_entry_bytes),
            ))
    }

    pub(super) fn estimate_execution_seed_snapshot_bytes(&self) -> u64 {
        let registers = u64::try_from(self.registers.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<Value>() as u64)
            .saturating_add(Self::saturating_sum(
                self.registers
                    .iter()
                    .map(Self::estimate_execution_seed_value_bytes),
            ));
        let heap = u64::try_from(self.heap.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<HeapObject>() as u64)
            .saturating_add(Self::saturating_sum(
                self.heap
                    .iter()
                    .map(Self::estimate_execution_seed_heap_object_bytes),
            ));
        let function_prototypes = u64::try_from(self.function_prototypes.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);
        let builtin_prototypes = Self::saturating_sum(self.builtin_prototypes.keys().map(|key| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(Self::estimate_string_bytes(key))
        }));
        registers
            .saturating_add(heap)
            .saturating_add(function_prototypes)
            .saturating_add(builtin_prototypes)
            .saturating_add(Self::estimate_symbol_state_bytes(&self.symbol_state))
            .saturating_add(Self::estimate_execution_seed_weakmap_storage_bytes(
                &self.weakmap_storage,
            ))
            .saturating_add(self.weak_collection_labels_memory_bytes())
    }

    pub(super) fn estimate_seed_surface_active_bytes(
        registers: &[Value],
        heap: &Heap,
        symbol_state: &RuntimeSymbolState,
        weakmap_storage: &BTreeMap<ObjectId, WeakMapStorage>,
        weak_collection_labels: &BTreeMap<ObjectId, Label>,
    ) -> u64 {
        Self::saturating_sum(registers.iter().map(Self::estimate_value_bytes))
            .saturating_add(heap.estimated_bytes())
            .saturating_add(Self::estimate_symbol_state_bytes(symbol_state))
            .saturating_add(Self::estimate_weakmap_storage_bytes(weakmap_storage))
            .saturating_add(Self::saturating_sum(
                weak_collection_labels
                    .values()
                    .map(Self::estimate_object_mutation_label_entry_bytes),
            ))
    }

    /// Reserve the owned map/set nodes and each copied value before a lazy
    /// seed can materialize. Use the bounded seed estimator for accessors.
    pub(super) fn estimate_execution_seed_weakmap_storage_bytes(
        storage: &BTreeMap<ObjectId, WeakMapStorage>,
    ) -> u64 {
        Self::saturating_sum(storage.values().map(|storage| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(std::mem::size_of::<(ObjectId, WeakMapStorage)>() as u64)
                .saturating_add(Self::saturating_sum(
                    storage
                        .entries
                        .values()
                        .chain(storage.symbol_entries.values())
                        .map(|value| {
                            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                                .saturating_mul(2)
                                .saturating_add(std::mem::size_of::<(u32, Value)>() as u64)
                                .saturating_add(Self::estimate_execution_seed_value_bytes(value))
                        }),
                ))
        }))
    }

    pub(super) fn weak_collection_labels_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.weakmap_storage
                .keys()
                .filter_map(|owner| self.object_mutation_labels.get(owner))
                .map(Self::estimate_object_mutation_label_entry_bytes),
        )
    }

    pub(super) fn estimate_plain_string_map_entry_bytes(key: &str, value: &Value) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(Self::estimate_string_bytes(key))
            .saturating_add(Self::estimate_value_bytes(value))
    }

    pub(super) fn estimate_js_string_map_entry_bytes(key: &JsString, value: &Value) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(Self::estimate_js_string_bytes(key))
            .saturating_add(Self::estimate_value_bytes(value))
    }

    pub(super) fn estimate_property_entry_bytes(key: &str, value: &Value) -> u64 {
        Self::estimate_plain_string_map_entry_bytes(key, value)
            // OrderedStringMap owns a second key for its ES-order
            // index/vector spine in addition to the lookup-map key.
            .saturating_add(Self::estimate_string_bytes(key))
    }

    /// Estimate the complete property carrier, including exact-key order
    /// sidecars activated only after a non-well-formed key is inserted.
    pub(super) fn estimate_ordered_property_map_bytes(properties: &OrderedStringMap<Value>) -> u64 {
        let exact_order_is_active = properties.exact_len() != properties.len();
        Self::saturating_sum(properties.well_formed_data_entries().map(|(key, value)| {
            let owned_key_copies =
                if exact_order_is_active && Self::canonical_array_index_key(key).is_none() {
                    // Lookup key + legacy insertion order + exact order + the
                    // frozen core-baseline chronology embedded in this carrier.
                    4
                } else {
                    // Lookup key + legacy numeric/string order spine.
                    2
                };
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_string_bytes(key).saturating_mul(owned_key_copies))
                .saturating_add(Self::estimate_value_bytes(value))
        }))
        .saturating_add(Self::saturating_sum(
            properties.exact_only_data_entries().map(|(key, value)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    // Exact lookup key + exact order + baseline chronology.
                    .saturating_add(Self::estimate_js_string_bytes(key).saturating_mul(3))
                    .saturating_add(Self::estimate_value_bytes(value))
            }),
        ))
        .saturating_add(Self::saturating_sum(
            properties
                .baseline_symbol_properties()
                .map(|(_, property)| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add((std::mem::size_of::<SymbolId>() as u64).saturating_mul(2))
                        .saturating_add(match property {
                            BaselineSymbolProperty::Data(value) => {
                                Self::estimate_value_bytes(value)
                            }
                            BaselineSymbolProperty::Accessor { get, set } => get
                                .as_ref()
                                .map(Self::estimate_value_bytes)
                                .unwrap_or(0)
                                .saturating_add(
                                    set.as_ref().map(Self::estimate_value_bytes).unwrap_or(0),
                                ),
                        })
                }),
        ))
    }

    pub(super) fn estimate_symbol_state_bytes(state: &RuntimeSymbolState) -> u64 {
        Self::saturating_sum(state.symbols.values().map(|record| {
            Self::estimate_symbol_record_bytes(
                record.description.as_ref(),
                record.registry_key.as_ref(),
            )
        }))
    }

    /// One dynamic symbol record and its derived registry index entry's term
    /// of [`Self::estimate_symbol_state_bytes`]. Including the index here makes
    /// eager budget admission, full walks, and execution seeds agree.
    pub(super) fn estimate_symbol_record_bytes(
        description: Option<&JsString>,
        registry_key: Option<&JsString>,
    ) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(description.map(Self::estimate_js_string_bytes).unwrap_or(0))
            .saturating_add(
                registry_key
                    .map(|key| {
                        Self::estimate_js_string_bytes(key)
                            .saturating_mul(2)
                            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
                            .saturating_add(std::mem::size_of::<SymbolId>() as u64)
                    })
                    .unwrap_or(0),
            )
    }

    pub(super) fn symbol_state_memory_bytes(&self) -> u64 {
        Self::estimate_symbol_state_bytes(&self.symbol_state)
    }

    pub(super) fn estimate_event_name_bytes(event: &RuntimePropertyKey) -> u64 {
        match event {
            RuntimePropertyKey::String(event) => Self::estimate_js_string_bytes(event),
            RuntimePropertyKey::Symbol(_) => std::mem::size_of::<SymbolId>() as u64,
        }
    }

    pub(super) fn estimate_event_listener_record_bytes(
        event: &RuntimePropertyKey,
        record: &EventListenerRecord,
    ) -> u64 {
        MEMORY_ESTIMATE_EVENT_LISTENER_BASE_BYTES
            .saturating_add(Self::estimate_event_name_bytes(event))
            .saturating_add(Self::estimate_value_bytes(&record.listener))
    }

    pub(super) fn estimate_event_promise_waiter_record_bytes(
        event: &RuntimePropertyKey,
        label: &Label,
    ) -> u64 {
        let label_bytes = match label {
            Label::Custom { name, .. } => Self::estimate_string_bytes(name),
            _ => 0,
        };
        MEMORY_ESTIMATE_EVENT_PROMISE_WAITER_BASE_BYTES
            .saturating_add(Self::estimate_event_name_bytes(event))
            .saturating_add(label_bytes)
    }

    pub(super) fn estimate_readable_to_array_waiter_bytes(label: &Label) -> u64 {
        let label_bytes = match label {
            Label::Custom { name, .. } => Self::estimate_string_bytes(name),
            _ => 0,
        };
        MEMORY_ESTIMATE_READABLE_TO_ARRAY_WAITER_BYTES.saturating_add(label_bytes)
    }

    pub(super) fn estimate_readable_buffer_bytes(buffer: &VecDeque<ReadableBufferedChunk>) -> u64 {
        u64::try_from(buffer.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(MEMORY_ESTIMATE_READABLE_BUFFERED_CHUNK_BYTES)
            .saturating_add(buffer.iter().fold(0u64, |total, chunk| {
                total
                    .saturating_add(Self::estimate_value_bytes(&chunk.value))
                    .saturating_add(Self::estimate_label_bytes(&chunk.label))
            }))
    }

    pub(super) fn estimate_readable_from_state_bytes(state: &ReadableFromState) -> u64 {
        let label_bytes = match &state.lifecycle_label {
            Label::Custom { name, .. } => Self::estimate_string_bytes(name),
            _ => 0,
        };
        MEMORY_ESTIMATE_READABLE_FROM_BASE_BYTES
            .saturating_add(Self::estimate_value_bytes(&state.source))
            .saturating_add(
                state
                    .read_callback
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::estimate_readable_buffer_bytes(&state.buffer))
            .saturating_add(u64::try_from(state.utf8_pending.capacity()).unwrap_or(u64::MAX))
            .saturating_add(
                state
                    .destroy_error
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(label_bytes)
            .saturating_add(
                state
                    .to_array_waiter
                    .as_ref()
                    .map(|waiter| Self::estimate_readable_to_array_waiter_bytes(&waiter.label))
                    .unwrap_or(0),
            )
    }

    pub(super) fn estimate_readable_terminal_state_bytes(state: &ReadableTerminalState) -> u64 {
        MEMORY_ESTIMATE_READABLE_TERMINAL_BASE_BYTES
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn estimate_label_bytes(label: &Label) -> u64 {
        match label {
            Label::Custom { name, .. } => Self::estimate_string_bytes(name),
            _ => 0,
        }
    }

    pub(super) fn estimate_value_vec_bytes(values: &[Value]) -> u64 {
        u64::try_from(values.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<Value>() as u64)
            .saturating_add(Self::saturating_sum(
                values.iter().map(Self::estimate_value_bytes),
            ))
    }

    pub(super) fn estimate_label_vec_bytes(labels: &[Label]) -> u64 {
        u64::try_from(labels.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<Label>() as u64)
            .saturating_add(Self::saturating_sum(
                labels.iter().map(Self::estimate_label_bytes),
            ))
    }

    pub(super) fn estimate_labeled_return_bytes(return_value: &LabeledReturn) -> u64 {
        Self::estimate_value_bytes(&return_value.value)
            .saturating_add(Self::estimate_label_bytes(&return_value.label))
    }

    pub(super) fn estimate_abrupt_completion_bytes(completion: &AbruptCompletion) -> u64 {
        match completion {
            AbruptCompletion::Exception(value, label) => {
                Self::estimate_value_bytes(value).saturating_add(Self::estimate_label_bytes(label))
            }
            AbruptCompletion::Return(return_value) => {
                Self::estimate_labeled_return_bytes(return_value)
            }
        }
    }

    pub(super) fn pending_abrupt_slots_memory_bytes(&self) -> u64 {
        self.pending_exception
            .as_ref()
            .map(Self::estimate_value_bytes)
            .unwrap_or(0)
            .saturating_add(Self::estimate_label_bytes(&self.pending_exception_label))
            .saturating_add(
                self.pending_return
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn replace_pending_abrupt_slots(
        &mut self,
        exception: Option<(Value, Label)>,
        return_value: Option<LabeledReturn>,
    ) -> Result<(), InterpreterError> {
        debug_assert!(
            exception.is_none() || return_value.is_none(),
            "pending exception and return are mutually exclusive"
        );
        let previous_bytes = self.pending_abrupt_slots_memory_bytes();
        let next_bytes = exception
            .as_ref()
            .map(|(value, label)| {
                Self::estimate_value_bytes(value).saturating_add(Self::estimate_label_bytes(label))
            })
            .unwrap_or(0)
            .saturating_add(
                return_value
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            );
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        match exception {
            Some((value, label)) => {
                self.pending_exception = Some(value);
                self.pending_exception_label = label;
            }
            None => {
                self.pending_exception = None;
                self.pending_exception_label = Label::Public;
            }
        }
        self.pending_return = return_value;
        Ok(())
    }

    pub(super) fn clear_pending_abrupt_slots(&mut self) {
        let released_bytes = self.pending_abrupt_slots_memory_bytes();
        self.pending_exception = None;
        self.pending_exception_label = Label::Public;
        self.pending_return = None;
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_pending_exception_slot(&mut self) {
        let released_bytes = self
            .pending_exception
            .as_ref()
            .map(Self::estimate_value_bytes)
            .unwrap_or(0)
            .saturating_add(Self::estimate_label_bytes(&self.pending_exception_label));
        self.pending_exception = None;
        self.pending_exception_label = Label::Public;
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn take_pending_exception_slot(&mut self) -> Option<(Value, Label)> {
        let value = self.pending_exception.take()?;
        let label = std::mem::replace(&mut self.pending_exception_label, Label::Public);
        let released_bytes =
            Self::estimate_value_bytes(&value).saturating_add(Self::estimate_label_bytes(&label));
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
        Some((value, label))
    }

    pub(super) fn take_pending_return_slot(&mut self) -> Option<LabeledReturn> {
        let value = self.pending_return.take()?;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_labeled_return_bytes(&value));
        Some(value)
    }

    pub(super) fn clear_suspended_abrupt_completions(&mut self) {
        // A nested callback clears only its own suspended completions.
        let floor = self
            .native_boundary_frame()
            .map_or(0, |frame| frame.saved_suspended_abrupt_depth)
            .min(self.suspended_abrupt_completions.len());
        let released = &self.suspended_abrupt_completions[floor..];
        let released_bytes = u64::try_from(released.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<AbruptCompletion>() as u64)
            .saturating_add(Self::saturating_sum(
                released.iter().map(Self::estimate_abrupt_completion_bytes),
            ));
        self.suspended_abrupt_completions.truncate(floor);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn replace_pending_hostcall_result_label(
        &mut self,
        label: Option<Label>,
    ) -> Result<(), InterpreterError> {
        let previous_bytes = self
            .pending_hostcall_result_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let next_bytes = label.as_ref().map(Self::estimate_label_bytes).unwrap_or(0);
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.pending_hostcall_result_label = label;
        Ok(())
    }

    pub(super) fn clear_pending_hostcall_result_label(&mut self) {
        let released_bytes = self
            .pending_hostcall_result_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        self.pending_hostcall_result_label = None;
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn take_pending_hostcall_result_label(&mut self) -> Option<Label> {
        let label = self.pending_hostcall_result_label.take()?;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&label));
        Some(label)
    }

    pub(super) fn join_pending_exception_label(
        &mut self,
        other: &Label,
    ) -> Result<(), InterpreterError> {
        let previous_bytes = Self::estimate_label_bytes(&self.pending_exception_label);
        let joined = self.pending_exception_label.join(other);
        let next_bytes = Self::estimate_label_bytes(&joined);
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.pending_exception_label = joined;
        Ok(())
    }

    pub(super) fn abrupt_completion_memory_bytes(&self) -> u64 {
        self.pending_abrupt_slots_memory_bytes()
            .saturating_add(
                self.pending_hostcall_result_label
                    .as_ref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                u64::try_from(self.suspended_abrupt_completions.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<AbruptCompletion>() as u64),
            )
            .saturating_add(Self::saturating_sum(
                self.suspended_abrupt_completions
                    .iter()
                    .map(Self::estimate_abrupt_completion_bytes),
            ))
            .saturating_add(self.finally_frames_memory_bytes())
    }

    pub(super) fn estimate_async_function_bytes(function: &AsyncFunctionObject) -> u64 {
        MEMORY_ESTIMATE_GENERATOR_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_CONTINUATION_OWNER_BYTES)
            .saturating_add(Self::estimate_value_vec_bytes(&function.saved_registers))
            .saturating_add(Self::estimate_label_vec_bytes(
                &function.saved_register_labels,
            ))
            .saturating_add(
                function
                    .isolated_execution
                    .as_ref()
                    .map(Self::estimate_held_activation_bytes)
                    .unwrap_or(0),
            )
    }

    /// Running total of the async-function records (bd-9vouw.57): each
    /// re-derivation re-measures only records borrowed mutably since.
    pub(super) fn async_functions_memory_bytes(&self) -> u64 {
        let bytes = self.async_functions.estimated_bytes();
        #[cfg(test)]
        debug_assert_eq!(
            bytes,
            self.async_functions_memory_bytes_by_walk(),
            "async-function running total drifted from the full walk"
        );
        bytes
    }

    pub(super) fn async_functions_memory_bytes_by_walk(&self) -> u64 {
        Self::saturating_sum(
            self.async_functions
                .iter()
                .map(Self::estimate_async_function_bytes),
        )
    }

    pub(super) fn push_generator_object(
        &mut self,
        generator: GeneratorObject,
    ) -> Result<u32, InterpreterError> {
        let id = u32::try_from(self.generators.len()).map_err(|_| InterpreterError::TypeError {
            expected: "generator table capacity".into(),
            got: format!("exceeded u32::MAX ({})", self.generators.len()),
        })?;
        // The component is a plain sum over the table, so appending changes it
        // by exactly the new object's bytes (bd-9vouw.31: no table walk).
        self.apply_memory_component_delta(0, Self::estimate_generator_bytes(&generator))?;
        if let Some(execution) = &generator.execution {
            self.closures.cold_cells.register_activation(execution);
        }
        self.generators.push(generator);
        Ok(id)
    }

    pub(super) fn pop_generator_object_and_release(&mut self) {
        if let Some(mut generator) = self.generators.pop() {
            let released_bytes = Self::estimate_generator_bytes(&generator);
            self.closures
                .replace_activation(&mut generator.execution, None);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(released_bytes);
        }
    }

    pub(super) fn push_async_function_object(
        &mut self,
        function: AsyncFunctionObject,
    ) -> Result<u32, InterpreterError> {
        let id =
            u32::try_from(self.async_functions.len()).map_err(|_| InterpreterError::TypeError {
                expected: "async function table capacity".into(),
                got: format!("exceeded u32::MAX ({})", self.async_functions.len()),
            })?;
        // Plain sum over the table: appending adds exactly the new object's
        // bytes (bd-9vouw.31: no table walk per async call).
        self.apply_memory_component_delta(0, Self::estimate_async_function_bytes(&function))?;
        if let Some(execution) = &function.isolated_execution {
            self.closures.cold_cells.register_activation(execution);
        }
        self.async_functions.push(function);
        Ok(id)
    }

    pub(super) fn pop_async_function_object_and_release(&mut self) {
        if let Some(mut function) = self.async_functions.pop() {
            let released_bytes = Self::estimate_async_function_bytes(&function);
            self.closures
                .replace_activation(&mut function.isolated_execution, None);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(released_bytes);
        }
    }

    pub(super) fn push_async_generator_object(
        &mut self,
        generator: AsyncGeneratorObject,
    ) -> Result<u32, InterpreterError> {
        let id = u32::try_from(self.async_generators.len()).map_err(|_| {
            InterpreterError::TypeError {
                expected: "async generator table capacity".into(),
                got: format!("exceeded u32::MAX ({})", self.async_generators.len()),
            }
        })?;
        let previous_bytes = self.async_generators_memory_bytes();
        self.async_generators.push(generator);
        let next_bytes = self.async_generators_memory_bytes();
        if let Err(error) = self.apply_memory_component_delta(previous_bytes, next_bytes) {
            self.async_generators.pop();
            return Err(error);
        }
        Ok(id)
    }

    pub(super) fn pop_async_generator_object_and_release(&mut self) {
        let previous_bytes = self.async_generators_memory_bytes();
        self.async_generators.pop();
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes.saturating_sub(self.async_generators_memory_bytes()));
    }

    pub(super) fn pending_io_callbacks_memory_bytes(&self) -> u64 {
        Self::saturating_sum(self.pending_io_callbacks.values().map(|arguments| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_value_vec_bytes(arguments))
        }))
    }

    pub(super) fn pending_fs_promise_read_bytes(task: &PendingFsPromiseRead) -> u64 {
        let value = match &task.outcome {
            Ok(value) | Err(value) => value,
        };
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<PendingFsPromiseRead>() as u64)
            .saturating_add(std::mem::size_of::<[usize; 2]>() as u64)
            .saturating_add(Self::estimate_value_bytes(value))
    }

    pub(super) fn pending_fs_promise_reads_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.pending_fs_promise_reads
                .values()
                .map(|task| Self::pending_fs_promise_read_bytes(task)),
        )
    }

    pub(super) fn pending_dynamic_import_task_bytes(task: &PendingDynamicImportTask) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<PendingDynamicImportTask>() as u64)
            .saturating_add(std::mem::size_of::<[usize; 2]>() as u64)
            .saturating_add(Self::estimate_string_bytes(&task.referrer))
            .saturating_add(Self::estimate_string_bytes(&task.specifier))
            .saturating_add(Self::estimate_label_bytes(&task.label))
            .saturating_add(
                task.cjs_context
                    .as_ref()
                    .map(|context| Self::estimate_string_bytes(&context.module_specifier))
                    .unwrap_or(0),
            )
            .saturating_add(
                task.inline_context_label
                    .as_ref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn pending_dynamic_imports_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.pending_dynamic_imports
                .values()
                .map(|task| Self::pending_dynamic_import_task_bytes(task)),
        )
    }

    pub(super) fn pending_child_process_tasks_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.pending_child_process_tasks
                .values()
                .map(Self::pending_child_process_task_bytes),
        )
    }

    pub(super) fn estimate_object_mutation_label_entry_bytes(label: &Label) -> u64 {
        (std::mem::size_of::<(ObjectId, Label)>() as u64)
            .saturating_add(64)
            .saturating_add(Self::estimate_label_bytes(label))
    }

    pub(super) fn object_mutation_labels_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.object_mutation_labels
                .values()
                .map(Self::estimate_object_mutation_label_entry_bytes),
        )
    }

    pub(super) fn estimate_pending_timer_task_bytes(task: &PendingTimerTask) -> u64 {
        match &task.kind {
            PendingTimerTaskKind::Callback {
                callback,
                args,
                label,
                ..
            } => MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_value_bytes(callback))
                .saturating_add(Self::estimate_value_vec_bytes(args))
                .saturating_add(Self::estimate_label_bytes(label)),
            PendingTimerTaskKind::PromiseResolve { value, .. } => MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(crate::promise_model::estimate_js_value_memory_bytes(value)),
        }
    }

    pub(super) fn pending_timer_tasks_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.pending_timer_tasks
                .values()
                .map(Self::estimate_pending_timer_task_bytes),
        )
    }

    pub(super) fn schedule_pending_timer_task(
        &mut self,
        task: PendingTimerTask,
        immediate: bool,
        delay_ms: u64,
    ) -> Result<u64, InterpreterError> {
        let retained_bytes = Self::estimate_pending_timer_task_bytes(&task);
        self.apply_memory_component_delta(0, retained_bytes)?;
        let (handler_id, label) = match &task.kind {
            PendingTimerTaskKind::Callback {
                callback, label, ..
            } => {
                let handler_id = match callback {
                    Value::Closure(id) | Value::Function(id) => *id,
                    _ => u32::MAX,
                };
                (handler_id, label.clone())
            }
            PendingTimerTaskKind::PromiseResolve { .. } => (u32::MAX, Label::Public),
        };
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let closure_handle = crate::closure_model::ClosureHandle(handler_id);
        let sequence = if immediate {
            self.event_loop.set_immediate(closure_handle, label)
        } else {
            self.event_loop.set_timeout(closure_handle, delay_ms, label)
        };
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            self.event_loop.rollback_last_scheduled(sequence);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            return Err(error);
        }
        self.pending_timer_tasks.insert(sequence, task);
        Ok(sequence)
    }

    pub(super) fn cancel_pending_timer_registration(&mut self, sequence: u64) {
        if let Some(task) = self.pending_timer_tasks.remove(&sequence) {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(Self::estimate_pending_timer_task_bytes(&task));
        }
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        self.event_loop.cancel_registration(sequence);
        let released_promise_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_promise_bytes);
    }

    pub(super) fn cancel_all_pending_timer_tasks(&mut self) {
        let pending_sequences = self.pending_timer_tasks.keys().copied().collect::<Vec<_>>();
        for sequence in pending_sequences {
            self.cancel_pending_timer_registration(sequence);
        }
        self.active_timers.clear();
        self.unref_timer_ids.clear();
    }

    pub(super) fn estimate_promise_combinator_bytes(state: &PromiseCombinatorState) -> u64 {
        match state {
            PromiseCombinatorState::All(tracker) => tracker.estimated_memory_bytes(),
            PromiseCombinatorState::AllSettled(tracker) => tracker.estimated_memory_bytes(),
            PromiseCombinatorState::Race(tracker) => tracker.estimated_memory_bytes(),
            PromiseCombinatorState::Any(tracker) => tracker.estimated_memory_bytes(),
        }
    }

    /// The combinator map's memory estimate: its running total
    /// (bd-9vouw.479). Unit tests check it against the full walk.
    pub(super) fn promise_combinators_memory_bytes(&self) -> u64 {
        #[cfg(test)]
        assert_eq!(
            self.promise_combinators_bytes,
            self.promise_combinators_memory_bytes_by_walk(),
            "promise combinator running total drifted from the walk"
        );
        self.promise_combinators_bytes
    }

    /// The watcher map's memory estimate: its running total (bd-9vouw.479).
    pub(super) fn promise_combinator_watchers_memory_bytes(&self) -> u64 {
        #[cfg(test)]
        assert_eq!(
            self.promise_combinator_watchers_bytes,
            self.promise_combinator_watchers_memory_bytes_by_walk(),
            "promise combinator watcher running total drifted from the walk"
        );
        self.promise_combinator_watchers_bytes
    }

    /// One combinator map entry's estimate.
    pub(super) fn promise_combinator_entry_bytes(state: &PromiseCombinatorState) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(Self::estimate_promise_combinator_bytes(state))
    }

    /// One watcher map entry's estimate, for `count` watchers.
    pub(super) fn promise_combinator_watcher_entry_bytes(count: usize) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(Self::promise_combinator_watchers_bytes_for(count))
    }

    /// The bytes `count` watchers take inside one watcher map entry.
    pub(super) fn promise_combinator_watchers_bytes_for(count: usize) -> u64 {
        u64::try_from(count)
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<PromiseCombinatorWatcher>() as u64)
    }

    pub(super) fn promise_combinators_memory_bytes_by_walk(&self) -> u64 {
        Self::saturating_sum(
            self.promise_combinators
                .values()
                .map(Self::promise_combinator_entry_bytes),
        )
    }

    pub(super) fn promise_combinator_watchers_memory_bytes_by_walk(&self) -> u64 {
        Self::saturating_sum(
            self.promise_combinator_watchers
                .values()
                .map(|watchers| Self::promise_combinator_watcher_entry_bytes(watchers.len())),
        )
    }

    /// Recount both running totals from the maps, after a bulk change.
    pub(super) fn resync_promise_combinator_bytes(&mut self) {
        self.promise_combinators_bytes = self.promise_combinators_memory_bytes_by_walk();
        self.promise_combinator_watchers_bytes =
            self.promise_combinator_watchers_memory_bytes_by_walk();
    }

    /// Owned footprint of the `process.nextTick` job queue (bd-8nrud).
    /// Charged as its own component (not part of `promise_runtime_memory_bytes`)
    /// so the Promise then/fulfill projected-delta preflights stay exact.
    pub(super) fn next_tick_queue_memory_bytes(&self) -> u64 {
        Self::saturating_sum(self.next_tick_queue.iter().map(|task| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_value_bytes(&task.callback))
                .saturating_add(Self::saturating_sum(
                    task.args.iter().map(Self::estimate_value_bytes),
                ))
                .saturating_add(Self::estimate_label_bytes(&task.label))
        }))
    }

    /// Owned footprint of the non-closure reaction-callable side table.
    /// Charged as its own component (not part of `promise_runtime_memory_bytes`)
    /// so the existing then/fulfill projected-delta preflights stay exact.
    pub(super) fn promise_reaction_callables_memory_bytes(&self) -> u64 {
        Self::saturating_sum(self.promise_reaction_callables.values().map(|value| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(Self::estimate_value_bytes(value))
        }))
    }

    pub(super) fn promise_runtime_memory_bytes(&self) -> u64 {
        self.promise_store
            .estimated_memory_bytes()
            .saturating_add(self.event_loop.estimated_memory_bytes())
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes)
    }

    /// Full-walk reference for [`Self::promise_runtime_memory_bytes`], used
    /// by the `recompute_estimated_memory_bytes` oracle (bd-9vouw.31).
    pub(super) fn promise_runtime_memory_bytes_by_walk(&self) -> u64 {
        self.promise_store
            .estimated_memory_bytes_by_walk()
            .saturating_add(self.event_loop.estimated_memory_bytes_by_walk())
            .saturating_add(self.promise_combinators_memory_bytes_by_walk())
            .saturating_add(self.promise_combinator_watchers_memory_bytes_by_walk())
            .saturating_add(self.promise_in_flight_task_bytes)
    }

    pub(super) fn begin_promise_task_transfer(&mut self, previous_promise_bytes: u64) -> u64 {
        let released_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_add(released_bytes);
        debug_assert_eq!(self.promise_runtime_memory_bytes(), previous_promise_bytes);
        released_bytes
    }

    pub(super) fn finish_promise_task_transfer(&mut self, transferred_bytes: u64) {
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_sub(transferred_bytes);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(transferred_bytes);
    }

    pub(super) fn weakmap_storage_memory_bytes(&self) -> u64 {
        Self::estimate_weakmap_storage_bytes(&self.weakmap_storage)
    }

    pub(super) fn estimate_weakmap_storage_bytes(
        storage: &BTreeMap<ObjectId, WeakMapStorage>,
    ) -> u64 {
        Self::saturating_sum(storage.values().map(|storage| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(Self::saturating_sum(
                storage
                    .entries
                    .values()
                    .chain(storage.symbol_entries.values())
                    .map(|value| {
                        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                            .saturating_mul(2)
                            .saturating_add(Self::estimate_value_bytes(value))
                    }),
            ))
        }))
    }

    pub(super) fn module_local_export_entry_bytes(
        name: &JsString,
        local: &Option<JsString>,
    ) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<(JsString, ModuleLocalExport)>() as u64)
            .saturating_add(Self::estimate_js_string_bytes(name))
            .saturating_add(
                local
                    .as_ref()
                    .map(Self::estimate_js_string_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn module_local_binding_index_bytes(local: &JsString) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<(JsString, ModuleLocalBinding)>() as u64)
            .saturating_add(Self::estimate_js_string_bytes(local))
    }

    pub(super) fn module_local_binding_export_bytes(name: &JsString) -> u64 {
        (std::mem::size_of::<JsString>() as u64)
            .saturating_add(Self::estimate_js_string_bytes(name))
    }

    pub(super) fn module_import_origin_entry_bytes(
        local: &JsString,
        origin: &ModuleImportOrigin,
    ) -> u64 {
        let payload = match origin {
            ModuleImportOrigin::Binding { specifier, name } => {
                Self::estimate_string_bytes(specifier)
                    .saturating_add(Self::estimate_js_string_bytes(name))
            }
            ModuleImportOrigin::Namespace { specifier } => Self::estimate_string_bytes(specifier),
        };
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<(JsString, ModuleImportOrigin)>() as u64)
            .saturating_add(Self::estimate_js_string_bytes(local))
            .saturating_add(payload)
    }

    pub(super) fn module_star_source_bytes(specifier: &str) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<String>() as u64)
            .saturating_add(Self::estimate_string_bytes(specifier))
    }

    pub(super) fn module_evaluation_exception_bytes((value, label): &(Value, Label)) -> u64 {
        Self::estimate_value_bytes(value).saturating_add(Self::estimate_label_bytes(label))
    }

    pub(super) fn module_exports_memory_bytes(&self) -> u64 {
        Self::saturating_sum(self.module_state.modules.values().map(|record| {
            let exports = Self::saturating_sum(
                record
                    .exports
                    .iter()
                    .map(|(name, value)| Self::estimate_js_string_map_entry_bytes(name, value)),
            );
            // The export record also retains the ceiling used to authorize
            // later imports. Custom labels own names even on failed records.
            let local_bindings =
                Self::saturating_sum(record.local_export_bindings.iter().map(|(name, local)| {
                    Self::module_local_export_entry_bytes(name, &local.local_name)
                }));
            let import_origins = Self::saturating_sum(
                record
                    .import_origins
                    .iter()
                    .map(|(local, origin)| Self::module_import_origin_entry_bytes(local, origin)),
            );
            let binding_indices = Self::saturating_sum(record.local_binding_indices.iter().map(
                |(local, binding)| {
                    Self::module_local_binding_index_bytes(local).saturating_add(
                        Self::saturating_sum(
                            binding
                                .exports
                                .iter()
                                .map(Self::module_local_binding_export_bytes),
                        ),
                    )
                },
            ));
            let star_sources = Self::saturating_sum(
                record
                    .star_sources
                    .iter()
                    .map(|source| Self::module_star_source_bytes(source)),
            );
            exports
                .saturating_add(local_bindings)
                .saturating_add(binding_indices)
                .saturating_add(import_origins)
                .saturating_add(star_sources)
                .saturating_add(
                    record
                        .evaluation_exception
                        .as_ref()
                        .map(Self::module_evaluation_exception_bytes)
                        .unwrap_or(0),
                )
                .saturating_add(
                    record
                        .flow_label_ceiling
                        .as_ref()
                        .map(Self::estimate_label_bytes)
                        .unwrap_or(0),
                )
        }))
    }

    pub(super) fn estimate_captured_state_bytes(state: &CapturedInterpreterState) -> u64 {
        u64::try_from(state.registers.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<CapturedRegisterState>() as u64)
            .saturating_add(Self::saturating_sum(state.registers.iter().map(|entry| {
                Self::estimate_value_bytes(&entry.value)
                    .saturating_add(Self::estimate_label_bytes(&entry.label))
            })))
            .saturating_add(
                u64::try_from(state.heap.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<CapturedHeapState>() as u64),
            )
            .saturating_add(Self::saturating_sum(state.heap.iter().map(|entry| {
                Self::estimate_heap_object_bytes(&entry.object)
                    .saturating_add(Self::estimate_label_bytes(&entry.label))
            })))
            .saturating_add(Self::estimate_symbol_state_bytes(&state.symbol_state))
    }

    pub(super) fn state_capture_memory_bytes(&self) -> u64 {
        self.state_capture_result
            .as_ref()
            .map(Self::estimate_captured_state_bytes)
            .unwrap_or(0)
    }

    pub(super) fn top_level_await_outcome_memory_bytes(&self) -> u64 {
        match &self.top_level_await_outcome {
            Some(Ok(completion)) => Self::estimate_labeled_return_bytes(completion),
            Some(Err(error)) => Self::estimate_interpreter_error_bytes(error),
            None => 0,
        }
    }

    pub(super) fn replace_top_level_await_outcome(
        &mut self,
        outcome: Result<LabeledReturn, InterpreterError>,
    ) {
        let previous_bytes = self.top_level_await_outcome_memory_bytes();
        let next_bytes = match &outcome {
            Ok(completion) => Self::estimate_labeled_return_bytes(completion),
            Err(error) => Self::estimate_interpreter_error_bytes(error),
        };
        match self.apply_memory_component_delta(previous_bytes, next_bytes) {
            Ok(_) => self.top_level_await_outcome = Some(outcome),
            Err(memory_error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(previous_bytes)
                    .saturating_add(Self::estimate_interpreter_error_bytes(&memory_error));
                self.top_level_await_outcome = Some(Err(memory_error));
            }
        }
    }

    pub(super) fn clear_top_level_await_outcome(&mut self) {
        let released_bytes = self.top_level_await_outcome_memory_bytes();
        self.top_level_await_outcome = None;
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn take_top_level_await_outcome(
        &mut self,
    ) -> Option<Result<LabeledReturn, InterpreterError>> {
        let released_bytes = self.top_level_await_outcome_memory_bytes();
        let outcome = self.top_level_await_outcome.take();
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
        outcome
    }

    /// Dynamic payload retained by a Writable-owned `Value`.
    ///
    /// Writable uses the same logical-ownership estimate as every other
    /// interpreter store so moves between registers, queues, and in-flight
    /// callbacks preserve one accounting algebra.
    pub(super) fn estimate_writable_value_bytes(value: &Value) -> u64 {
        Self::estimate_value_bytes(value)
    }

    pub(super) fn estimate_writable_callback_bytes(callback: &WritableCallbackRecord) -> u64 {
        Self::estimate_writable_value_bytes(&callback.value)
            .saturating_add(Self::estimate_label_bytes(&callback.label))
            .saturating_add(
                callback
                    .module_specifier
                    .as_ref()
                    .map(|specifier| Self::estimate_string_bytes(specifier))
                    .unwrap_or(0),
            )
    }

    pub(super) fn estimate_writable_write_record_bytes(record: &WritableWriteRecord) -> u64 {
        MEMORY_ESTIMATE_WRITABLE_WRITE_NODE_BYTES
            .saturating_add(Self::estimate_writable_value_bytes(&record.value))
            .saturating_add(Self::estimate_label_bytes(&record.label))
            .saturating_add(
                record
                    .callback
                    .as_ref()
                    .map(Self::estimate_writable_callback_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn estimate_writable_error_dynamic_bytes(state: &WritableState) -> u64 {
        let terminal = state
            .terminal_error
            .as_ref()
            .map(|(value, label)| {
                Self::estimate_writable_value_bytes(value)
                    .saturating_add(Self::estimate_label_bytes(label))
            })
            .unwrap_or(0);
        Self::estimate_label_bytes(&state.lifecycle_label).saturating_add(terminal)
    }

    pub(super) fn estimate_interpreter_error_bytes(error: &InterpreterError) -> u64 {
        let string = Self::estimate_string_bytes;
        match error {
            InterpreterError::TypeError { expected, got } => {
                string(expected).saturating_add(string(got))
            }
            InterpreterError::RangeError { message }
            | InterpreterError::UncaughtException { value: message }
            | InterpreterError::InternalError { details: message }
            | InterpreterError::Terminated { reason: message } => string(message),
            InterpreterError::PropertyNotFound { key, .. }
            | InterpreterError::ImportSpecifierNotString { got: key }
            | InterpreterError::RequireSpecifierNotString { got: key }
            | InterpreterError::ExportOutsideModule { name: key }
            | InterpreterError::CapabilityDenied { capability: key }
            | InterpreterError::UnsupportedMembershipSemantics { operator: key }
            | InterpreterError::UninitializedBinding { name: key }
            | InterpreterError::UndefinedBinding { name: key }
            | InterpreterError::ConstAssignment { name: key } => string(key),
            InterpreterError::ModuleResolutionFailed { specifier, reason } => string(specifier)
                .saturating_add(match reason {
                    ModuleResolutionFailureReason::Other(reason) => string(reason),
                    ModuleResolutionFailureReason::BareSpecifiersNotSupported
                    | ModuleResolutionFailureReason::MalformedSpecifier
                    | ModuleResolutionFailureReason::ModuleNotFound
                    | ModuleResolutionFailureReason::PackagePathNotExported
                    | ModuleResolutionFailureReason::PackageImportNotDefined
                    | ModuleResolutionFailureReason::NativeAddonUnsupported => 0,
                }),
            InterpreterError::ModuleReadFailed { specifier, error }
            | InterpreterError::ModuleParseFailed { specifier, error }
            | InterpreterError::ModuleLoweringFailed { specifier, error } => {
                string(specifier).saturating_add(string(error))
            }
            InterpreterError::ModuleEvaluationFailed { specifier, reason } => {
                string(specifier).saturating_add(string(reason))
            }
            InterpreterError::HostFilesystem { code, message } => {
                string(code).saturating_add(string(message))
            }
            InterpreterError::HostProcess {
                code,
                message,
                stdout,
                stderr,
                ..
            } => string(code)
                .saturating_add(string(message))
                .saturating_add(u64::try_from(stdout.len()).unwrap_or(u64::MAX))
                .saturating_add(u64::try_from(stderr.len()).unwrap_or(u64::MAX)),
            InterpreterError::ContainmentActionRequested { action, reason } => string(action)
                .saturating_add(reason.as_ref().map(|reason| string(reason)).unwrap_or(0)),
            InterpreterError::BudgetExhausted { .. }
            | InterpreterError::RegisterOutOfBounds { .. }
            | InterpreterError::InstructionOutOfBounds { .. }
            | InterpreterError::StackOverflow { .. }
            | InterpreterError::DivisionByZero
            | InterpreterError::ProcessExit { .. }
            | InterpreterError::UndefinedRegister { .. }
            | InterpreterError::ObjectNotFound { .. }
            | InterpreterError::FunctionNotFound { .. }
            | InterpreterError::StringPoolOutOfBounds { .. }
            | InterpreterError::IteratorNotFound { .. }
            | InterpreterError::Halted
            | InterpreterError::StringLimitExceeded { .. }
            | InterpreterError::MemoryBudgetExceeded { .. }
            | InterpreterError::ScopeDepthExceeded { .. }
            | InterpreterError::ConsoleBudgetExceeded { .. }
            | InterpreterError::Cancelled => 0,
        }
    }

    pub(super) fn estimate_writable_state_without_writes_bytes(state: &WritableState) -> u64 {
        MEMORY_ESTIMATE_WRITABLE_BASE_BYTES
            .saturating_add(
                state
                    .write_callback
                    .as_ref()
                    .map(Self::estimate_writable_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                state
                    .final_callback
                    .as_ref()
                    .map(Self::estimate_writable_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                u64::try_from(state.end_callbacks.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES),
            )
            .saturating_add(state.end_callbacks.iter().fold(0u64, |total, record| {
                total.saturating_add(Self::estimate_writable_callback_bytes(&record.callback))
            }))
            .saturating_add(
                state
                    .terminal_error
                    .as_ref()
                    .map(|(value, label)| {
                        Self::estimate_writable_value_bytes(value)
                            .saturating_add(Self::estimate_label_bytes(label))
                    })
                    .unwrap_or(0),
            )
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn estimate_writable_state_bytes(state: &WritableState) -> u64 {
        Self::estimate_writable_state_without_writes_bytes(state)
            .saturating_add(state.writes.retained_bytes())
    }

    pub(super) fn recompute_writable_state_bytes(state: &WritableState) -> u64 {
        Self::estimate_writable_state_without_writes_bytes(state)
            .saturating_add(state.writes.recompute_retained_bytes())
    }

    pub(super) fn estimate_writable_terminal_state_bytes(state: &WritableTerminalState) -> u64 {
        MEMORY_ESTIMATE_WRITABLE_TERMINAL_BASE_BYTES
            .saturating_add(
                u64::try_from(state.callbacks.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES),
            )
            .saturating_add(state.callbacks.iter().fold(0u64, |total, record| {
                total.saturating_add(Self::estimate_writable_callback_bytes(&record.callback))
            }))
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn estimate_scope_bindings_bytes(bindings: &BTreeMap<String, ScopeBinding>) -> u64 {
        Self::saturating_sum(bindings.iter().map(|(name, binding)| {
            let state_bytes = binding
                .state
                .try_borrow()
                .map(|state| {
                    Self::estimate_value_bytes(&state.value)
                        .saturating_add(std::mem::size_of::<Label>() as u64)
                        .saturating_add(Self::estimate_label_bytes(&state.label))
                })
                .unwrap_or(u64::MAX);
            MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES
                .saturating_add(Self::estimate_string_bytes(name))
                .saturating_add(state_bytes)
        }))
    }

    /// Per-alias model: structural bytes plus the shared cell payload counted
    /// for every binding entry. Retained for surfaces deliberately kept
    /// conservative (realm-global maps, which live outside the deduped payload
    /// walk) and for tests that pin the per-alias model.
    #[allow(dead_code)]
    pub(super) fn estimate_scope_frame_bytes(frame: &ScopeFrame) -> u64 {
        MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES
            .saturating_add(Self::estimate_scope_bindings_bytes(&frame.bindings))
    }

    /// Per-alias structural bytes of a scope chain: frame bases plus binding
    /// entry bases and names. The shared cell payload behind each binding's
    /// `Rc` is deliberately excluded — clones of a frame share the physical
    /// `ScopeBindingState`, so the payload is charged exactly once per
    /// distinct cell by [`Self::shared_binding_cell_payloads_memory_bytes`]
    /// instead of once per alias (bd-sblaq).
    pub(super) fn estimate_scope_chain_bytes(frames: &[ScopeFrame]) -> u64 {
        Self::estimate_scope_chain_shallow_clone_bytes(frames)
    }

    /// One slot per frame of a chain whose frame maps are charged elsewhere,
    /// once per distinct map: by the cold-cell ledger, or by the live-only
    /// walk for the live chain and the top saved chain (bd-9vouw.154).
    pub(super) fn estimate_scope_chain_slot_bytes(frames: &[ScopeFrame]) -> u64 {
        u64::try_from(frames.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES)
    }

    /// Key bytes of a chain's frame maps, counted per alias.
    pub(super) fn scope_chain_key_bytes(frames: &[ScopeFrame]) -> u64 {
        Self::saturating_sum(frames.iter().map(|frame| frame.key_bytes))
    }

    /// Physical payload owned by one shared lexical binding cell: the
    /// `ScopeBindingState` allocation plus the estimated bytes of its value
    /// and IFC label (bd-sblaq).
    pub(super) fn estimate_binding_cell_payload_bytes(
        state: &Rc<RefCell<ScopeBindingState>>,
    ) -> u64 {
        state
            .try_borrow()
            .map(|state| {
                (std::mem::size_of::<ScopeBindingState>() as u64)
                    .saturating_add(Self::estimate_value_bytes(&state.value))
                    .saturating_add(Self::estimate_label_bytes(&state.label))
            })
            .unwrap_or(u64::MAX)
    }

    /// Add every not-yet-seen binding cell payload in `frames` to the running
    /// total, recording each physical cell in `seen` by `Rc` address so
    /// aliases across frames, closures, and suspended activations charge the
    /// payload exactly once (bd-sblaq).
    pub(super) fn accumulate_scope_frame_cell_payload_bytes(
        frames: &[ScopeFrame],
        seen_cells: &mut BTreeSet<usize>,
        seen_maps: &mut BTreeSet<usize>,
    ) -> u64 {
        let mut total = 0u64;
        for frame in frames {
            // Equal Rc map identities contain the same cells. COW maps must
            // still be inspected, and their shared cells deduplicated below.
            // This local proof reads no cold-ledger membership or totals.
            if !seen_maps.insert(Rc::as_ptr(&frame.bindings) as usize) {
                continue;
            }
            for binding in frame.bindings.values() {
                if seen_cells.insert(Rc::as_ptr(&binding.state) as usize) {
                    total = total
                        .saturating_add(Self::estimate_binding_cell_payload_bytes(&binding.state));
                }
            }
        }
        total
    }

    /// Payloads reachable from one suspended activation: its scope chain plus
    /// every call frame's saved caller chain.
    pub(super) fn accumulate_generator_execution_cell_payload_bytes(
        execution: &GeneratorExecutionSnapshot,
        seen_cells: &mut BTreeSet<usize>,
        seen_maps: &mut BTreeSet<usize>,
    ) -> u64 {
        let mut total = Self::accumulate_scope_frame_cell_payload_bytes(
            &execution.scope_chain.frames,
            seen_cells,
            seen_maps,
        );
        for frame in &execution.call_stack {
            if let Some(saved) = &frame.saved_scope_chain {
                total = total.saturating_add(Self::accumulate_scope_frame_cell_payload_bytes(
                    saved, seen_cells, seen_maps,
                ));
            }
        }
        total
    }

    /// Payload bytes of every shared lexical binding cell reachable from the
    /// deduped accounting surfaces — the live scope chain, call-frame saved
    /// caller chains, closure captured environments, and suspended
    /// generator/async activations — charged exactly once per physical
    /// `Rc<RefCell<ScopeBindingState>>` (bd-sblaq). Realm-global maps stay on
    /// the conservative per-alias model outside this walk, so a cell aliased
    /// both here and there is over-counted, never under-counted.
    pub(super) fn shared_binding_cell_payloads_memory_bytes(&self) -> u64 {
        // Every invocation independently inspects each physical map and cell.
        // Never reuse visited maps from key accounting or cached ledger state.
        let mut seen_cells = BTreeSet::new();
        let mut seen_maps = BTreeSet::new();
        let mut total = Self::accumulate_scope_frame_cell_payload_bytes(
            &self.scope_chain.frames,
            &mut seen_cells,
            &mut seen_maps,
        );
        for frame in self.call_stack.iter() {
            if let Some(saved) = &frame.saved_scope_chain {
                total = total.saturating_add(Self::accumulate_scope_frame_cell_payload_bytes(
                    saved,
                    &mut seen_cells,
                    &mut seen_maps,
                ));
            }
        }
        for closure in self.closures.iter() {
            total = total.saturating_add(Self::accumulate_scope_frame_cell_payload_bytes(
                &closure.captured_env,
                &mut seen_cells,
                &mut seen_maps,
            ));
        }
        for generator in self.generators.iter() {
            if let Some(execution) = &generator.execution {
                total =
                    total.saturating_add(Self::accumulate_generator_execution_cell_payload_bytes(
                        execution,
                        &mut seen_cells,
                        &mut seen_maps,
                    ));
            }
        }
        for function in self.async_functions.iter() {
            if let Some(execution) = &function.isolated_execution {
                total =
                    total.saturating_add(Self::accumulate_generator_execution_cell_payload_bytes(
                        execution,
                        &mut seen_cells,
                        &mut seen_maps,
                    ));
            }
        }
        for binding in self
            .mapped_argument_bindings
            .values()
            .flat_map(|bindings| bindings.values())
        {
            if seen_cells.insert(ColdBindingCells::key(&binding.state)) {
                total =
                    total.saturating_add(Self::estimate_binding_cell_payload_bytes(&binding.state));
            }
        }
        for entry in &self.module_state.live_exports {
            if seen_cells.insert(ColdBindingCells::key(&entry.cell)) {
                total =
                    total.saturating_add(Self::estimate_binding_cell_payload_bytes(&entry.cell));
            }
        }
        total
    }

    /// Bytes allocated by cloning scope-frame structure while sharing each
    /// binding cell. Mutable cell payloads are deliberately excluded: charging
    /// them here would make a fixed snapshot charge drift whenever the shared
    /// live binding changes size.
    pub(super) fn estimate_scope_chain_shallow_clone_bytes(frames: &[ScopeFrame]) -> u64 {
        Self::saturating_sum(frames.iter().map(|frame| {
            debug_assert_eq!(
                frame.key_bytes,
                Self::saturating_sum(
                    frame
                        .bindings
                        .keys()
                        .map(|name| ScopeFrame::binding_key_bytes(name))
                ),
                "cached scope-frame key bytes drifted from the bindings"
            );
            MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES.saturating_add(frame.key_bytes)
        }))
    }

    pub(super) fn estimate_call_frame_bytes(frame: &CallFrame) -> u64 {
        MEMORY_ESTIMATE_CALL_FRAME_BASE_BYTES
            .saturating_add(Self::estimate_value_bytes(&frame.this_value))
            .saturating_add(Self::estimate_label_bytes(&frame.this_label))
            .saturating_add(Self::estimate_value_bytes(&frame.new_target_value))
            .saturating_add(Self::estimate_label_bytes(&frame.new_target_label))
            .saturating_add(Self::estimate_value_bytes(&frame.super_value))
            .saturating_add(Self::estimate_label_bytes(&frame.super_label))
            .saturating_add(std::mem::size_of::<Option<ObjectId>>() as u64)
            .saturating_add(
                frame
                    .construct_this
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_pending_exception
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::estimate_label_bytes(
                &frame.saved_pending_exception_label,
            ))
            .saturating_add(
                frame
                    .saved_pending_return
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_scope_chain
                    .as_ref()
                    .map_or(0, |frames| Self::estimate_scope_chain_bytes(frames)),
            )
            .saturating_add(frame.scope_inert_virtual_scope_bytes)
    }

    /// A frame of the live call stack: [`Self::estimate_call_frame_bytes`]
    /// with its saved caller chain charged one slot per frame. The chain's
    /// maps are charged once each by the cold-cell ledger (frames below the
    /// top) or by the live-only scope walk (the top frame) (bd-9vouw.154).
    pub(super) fn estimate_live_call_frame_bytes(frame: &CallFrame) -> u64 {
        Self::estimate_call_frame_bytes(frame).saturating_sub(
            frame
                .saved_scope_chain
                .as_deref()
                .map_or(0, Self::scope_chain_key_bytes),
        )
    }

    pub(super) fn estimate_call_frame_snapshot_clone_bytes(frame: &CallFrame) -> u64 {
        MEMORY_ESTIMATE_CALL_FRAME_BASE_BYTES
            .saturating_add(Self::estimate_value_bytes(&frame.this_value))
            .saturating_add(Self::estimate_label_bytes(&frame.this_label))
            .saturating_add(Self::estimate_value_bytes(&frame.new_target_value))
            .saturating_add(Self::estimate_label_bytes(&frame.new_target_label))
            .saturating_add(Self::estimate_value_bytes(&frame.super_value))
            .saturating_add(Self::estimate_label_bytes(&frame.super_label))
            .saturating_add(std::mem::size_of::<Option<ObjectId>>() as u64)
            .saturating_add(
                frame
                    .construct_this
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_pending_exception
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::estimate_label_bytes(
                &frame.saved_pending_exception_label,
            ))
            .saturating_add(
                frame
                    .saved_pending_return
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(frame.saved_scope_chain.as_ref().map_or(0, |frames| {
                Self::estimate_scope_chain_shallow_clone_bytes(frames)
            }))
            .saturating_add(frame.scope_inert_virtual_scope_bytes)
    }

    /// Footprint of one sparse non-default property-attribute entry.
    pub(super) fn estimate_property_attributes_entry_bytes(key: &RuntimePropertyKey) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(match key {
            RuntimePropertyKey::String(key) => Self::estimate_js_string_bytes(key),
            RuntimePropertyKey::Symbol(_) => 0,
        })
    }

    pub(super) fn estimate_heap_object_bytes(object: &HeapObject) -> u64 {
        let properties = Self::estimate_ordered_property_map_bytes(&object.properties);
        let property_labels =
            Self::estimate_execution_seed_ordered_label_map_bytes(&object.property_labels);
        let property_attributes = Self::saturating_sum(
            object
                .property_attributes
                .keys()
                .map(Self::estimate_property_attributes_entry_bytes),
        );
        let array_buffer_bytes = object
            .array_buffer
            .as_ref()
            .map(|backing| {
                (backing.bytes.len() as u64)
                    .saturating_add(Self::estimate_label_bytes(&backing.label))
                    // bd-9vouw.256: a resizable buffer's view registry.
                    .saturating_add((backing.views.len() * std::mem::size_of::<ObjectId>()) as u64)
            })
            .unwrap_or(0);
        let typed_array_bytes = object
            .typed_array
            .as_ref()
            .map(|_| MEMORY_ESTIMATE_TYPED_ARRAY_VIEW_BYTES)
            .unwrap_or(0);
        let data_view_bytes = object
            .data_view
            .as_ref()
            .map(|_| MEMORY_ESTIMATE_DATA_VIEW_BYTES)
            .unwrap_or(0);
        let blob_bytes = object
            .blob
            .as_ref()
            .map(|blob| (blob.bytes.len() as u64).saturating_add(blob.content_type.len() as u64))
            .unwrap_or(0)
            .saturating_add(
                object
                    .regexp
                    .as_ref()
                    .map_or(0, |slots| (slots.source.len() + slots.flags.len()) as u64),
            );
        MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES
            .saturating_add(properties)
            .saturating_add(property_labels)
            .saturating_add(property_attributes)
            .saturating_add(
                object
                    .date_value
                    .as_ref()
                    .map_or(0, |_| std::mem::size_of::<Float64>() as u64),
            )
            .saturating_add(
                object
                    .collection_storage
                    .as_ref()
                    .map_or(0, |_| std::mem::size_of::<ObjectId>() as u64),
            )
            .saturating_add(array_buffer_bytes)
            .saturating_add(typed_array_bytes)
            .saturating_add(data_view_bytes)
            .saturating_add(blob_bytes)
            .saturating_add(
                object
                    .derived_constructor_parent
                    .as_deref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                object
                    .class_fields
                    .as_deref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                object
                    .primitive_value
                    .as_deref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::estimate_brand_bytes(object.brand.as_deref()))
            .saturating_add(Self::saturating_sum(
                object
                    .private_elements
                    .values()
                    .map(Self::estimate_private_element_bytes),
            ))
            .saturating_add(
                object
                    .derived_constructor_parent_label
                    .as_deref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::saturating_sum(
                object
                    .deleted_virtual_keys
                    .iter()
                    .map(Self::estimate_property_attributes_entry_bytes),
            ))
    }

    /// Footprint of one [[PrivateElements]] entry.
    pub(super) fn estimate_private_element_bytes(element: &PrivateElement) -> u64 {
        let label = match element {
            PrivateElement::Field { label, .. } => Self::estimate_label_bytes(label),
            PrivateElement::Method { .. } | PrivateElement::Accessor { .. } => 0,
        };
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(label)
            .saturating_add(Self::saturating_sum(
                element.values().map(Self::estimate_value_bytes),
            ))
    }

    pub(super) fn estimate_iterator_bytes(iterator: &RuntimeIteratorState) -> u64 {
        match iterator {
            RuntimeIteratorState::ForIn(state) => {
                let keys =
                    Self::saturating_sum(state.keys.iter().map(Self::estimate_js_string_bytes));
                MEMORY_ESTIMATE_ITERATOR_BASE_BYTES.saturating_add(keys)
            }
            RuntimeIteratorState::ForOf(state) => {
                let value_slots = u64::try_from(state.values.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<Value>() as u64);
                let values =
                    Self::saturating_sum(state.values.iter().map(Self::estimate_value_bytes));
                let next_method = state
                    .next_method
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0);
                let timers_interval = state
                    .timers_interval
                    .as_ref()
                    .map(|(_, value)| Self::estimate_value_bytes(value))
                    .unwrap_or(0);
                MEMORY_ESTIMATE_ITERATOR_BASE_BYTES
                    .saturating_add(value_slots)
                    .saturating_add(values)
                    .saturating_add(
                        state
                            .array
                            .as_ref()
                            .map_or(0, |_| std::mem::size_of::<RuntimeArrayIterator>() as u64),
                    )
                    // A collection iterator and its `collection_iterators`
                    // registry entry.
                    .saturating_add(state.collection.as_ref().map_or(0, |_| {
                        (std::mem::size_of::<RuntimeCollectionIterator>() as u64)
                            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
                    }))
                    .saturating_add(next_method)
                    .saturating_add(
                        state
                            .iterator_receiver
                            .as_ref()
                            .map(Self::estimate_value_bytes)
                            .unwrap_or(0),
                    )
                    .saturating_add(timers_interval)
            }
        }
    }

    pub(super) fn estimate_generator_invocation_bytes(invocation: &GeneratorInvocation) -> u64 {
        Self::estimate_value_vec_bytes(&invocation.arguments)
            .saturating_add(Self::estimate_label_vec_bytes(&invocation.argument_labels))
            .saturating_add(Self::estimate_value_bytes(&invocation.this_value))
            .saturating_add(Self::estimate_label_bytes(&invocation.this_label))
            .saturating_add(
                invocation
                    .inline_context_label
                    .as_ref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                invocation
                    .module_specifier
                    .as_deref()
                    .map(Self::estimate_string_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn estimate_generator_delegation_bytes(delegation: &GeneratorDelegation) -> u64 {
        (std::mem::size_of::<GeneratorDelegation>() as u64)
            .saturating_add(Self::estimate_label_bytes(&delegation.label))
    }

    pub(super) fn generator_delegation_memory_bytes(&self) -> u64 {
        self.generator_delegation
            .as_ref()
            .map(Self::estimate_generator_delegation_bytes)
            .unwrap_or(0)
    }

    /// `estimate_value_vec_bytes` of a snapshot's register file plus
    /// `estimate_label_vec_bytes` of its label file, from the byte totals
    /// the snapshot carries when it has them (bd-9vouw.500): the transfer
    /// accounting of every generator step and await summed both files of
    /// the parked activation and of the caller.
    pub(super) fn snapshot_register_files_bytes(execution: &GeneratorExecutionSnapshot) -> u64 {
        let slots = |len: usize, slot: usize| {
            u64::try_from(len)
                .unwrap_or(u64::MAX)
                .saturating_mul(slot as u64)
        };
        let values = match execution.registers_value_bytes {
            Some(bytes) => {
                slots(execution.registers.len(), std::mem::size_of::<Value>()).saturating_add(bytes)
            }
            None => Self::estimate_value_vec_bytes(&execution.registers),
        };
        let labels = match execution.register_labels_bytes {
            Some(bytes) => slots(
                execution.register_labels.len(),
                std::mem::size_of::<Label>(),
            )
            .saturating_add(bytes),
            None => Self::estimate_label_vec_bytes(&execution.register_labels),
        };
        debug_assert_eq!(
            (values, labels),
            (
                Self::estimate_value_vec_bytes(&execution.registers),
                Self::estimate_label_vec_bytes(&execution.register_labels)
            ),
            "a parked snapshot's byte totals went stale (bd-9vouw.500)"
        );
        values.saturating_add(labels)
    }

    pub(super) fn estimate_generator_execution_bytes(
        execution: &GeneratorExecutionSnapshot,
    ) -> u64 {
        let pending_abrupt = execution
            .pending_exception
            .as_ref()
            .map(Self::estimate_value_bytes)
            .unwrap_or(0)
            .saturating_add(Self::estimate_label_bytes(
                &execution.pending_exception_label,
            ))
            .saturating_add(
                execution
                    .pending_return
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            );
        let suspended_abrupt = u64::try_from(execution.suspended_abrupt_completions.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<AbruptCompletion>() as u64)
            .saturating_add(Self::saturating_sum(
                execution
                    .suspended_abrupt_completions
                    .iter()
                    .map(Self::estimate_abrupt_completion_bytes),
            ));
        let finally_frames = Self::saturating_sum(
            execution
                .finally_frames
                .iter()
                .map(Self::finally_frame_memory_bytes),
        );

        Self::snapshot_register_files_bytes(execution)
            .saturating_add(
                execution
                    .delegation
                    .as_ref()
                    .map(Self::estimate_generator_delegation_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                execution
                    .active_inline_callback_context_label
                    .as_ref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::saturating_sum(
                execution
                    .call_stack
                    .iter()
                    .map(Self::estimate_call_frame_bytes),
            ))
            .saturating_add(
                u64::try_from(execution.catch_frames.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<CatchFrame>() as u64),
            )
            .saturating_add(pending_abrupt)
            .saturating_add(
                execution
                    .pending_hostcall_result_label
                    .as_ref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(suspended_abrupt)
            .saturating_add(finally_frames)
            .saturating_add(Self::estimate_scope_chain_bytes(
                &execution.scope_chain.frames,
            ))
            .saturating_add(
                u64::try_from(execution.pending_captures.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<u32>() as u64),
            )
            .saturating_add(
                execution
                    .current_module_specifier
                    .as_deref()
                    .map(Self::estimate_string_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                execution
                    .contained_codegen_grant
                    .map(|_| std::mem::size_of::<ContainedCodegenGrant>() as u64)
                    .unwrap_or(0),
            )
    }

    pub(super) fn estimate_generator_bytes(generator: &GeneratorObject) -> u64 {
        MEMORY_ESTIMATE_GENERATOR_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_CONTINUATION_OWNER_BYTES)
            .saturating_add(
                generator
                    .invocation
                    .as_ref()
                    .map(Self::estimate_generator_invocation_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                generator
                    .execution
                    .as_ref()
                    .map(Self::estimate_held_activation_bytes)
                    .unwrap_or(0),
            )
    }

    /// A suspended activation the cold-cell ledger holds (a generator's or
    /// an isolated async call's): [`Self::estimate_generator_execution_bytes`]
    /// less the key bytes of its scope chain and saved caller chains, which
    /// the ledger charges once per distinct map (bd-9vouw.154). A snapshot
    /// the ledger does not hold (a caller set aside during an isolated call)
    /// keeps the per-alias estimate.
    pub(super) fn estimate_held_activation_bytes(execution: &GeneratorExecutionSnapshot) -> u64 {
        let key_bytes = Self::scope_chain_key_bytes(&execution.scope_chain.frames).saturating_add(
            Self::saturating_sum(execution.call_stack.iter().map(|frame| {
                frame
                    .saved_scope_chain
                    .as_deref()
                    .map_or(0, Self::scope_chain_key_bytes)
            })),
        );
        Self::estimate_generator_execution_bytes(execution).saturating_sub(key_bytes)
    }

    pub(super) fn estimate_generators_bytes<'a>(
        generators: impl Iterator<Item = &'a GeneratorObject>,
    ) -> u64 {
        Self::saturating_sum(generators.map(Self::estimate_generator_bytes))
    }

    /// A closure's own structure: its base plus one slot per captured frame.
    /// The frame maps are shared, so the cold-cell ledger charges their key
    /// bytes once per distinct map (bd-9vouw.154). A reclaimed closure is
    /// charged nothing: its entry is released with its chunk (bd-9vouw.57).
    pub(super) fn estimate_closure_alias_bytes(closure: &ClosureValue) -> u64 {
        if closure.function_index == RECLAIMED_CLOSURE_FUNCTION_INDEX {
            return 0;
        }
        MEMORY_ESTIMATE_CLOSURE_BASE_BYTES
            .saturating_add(Self::estimate_scope_chain_slot_bytes(&closure.captured_env))
    }

    pub(super) fn estimate_closures_bytes<'a>(
        closures: impl Iterator<Item = &'a ClosureValue>,
    ) -> u64 {
        Self::saturating_sum(closures.map(Self::estimate_closure_alias_bytes))
    }

    pub(super) fn estimate_closure_method_metadata_entry_bytes(
        metadata: &ClosureMethodMetadata,
    ) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<u32>() as u64)
            .saturating_add(std::mem::size_of::<ObjectId>() as u64)
            .saturating_add(Self::estimate_js_string_bytes(&metadata.name))
            .saturating_add(Self::estimate_label_bytes(&metadata.definition_label))
    }

    pub(super) fn estimate_closure_lexical_super_metadata_entry_bytes(
        metadata: &ClosureLexicalSuperMetadata,
    ) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<u32>() as u64)
            .saturating_add(std::mem::size_of::<ObjectId>() as u64)
            .saturating_add(Self::estimate_label_bytes(&metadata.definition_label))
            .saturating_add(Self::estimate_value_bytes(&metadata.this_value))
            .saturating_add(Self::estimate_label_bytes(&metadata.this_label))
    }

    /// bd-asw4m.3: bytes for one `arrow_lexical_this` entry (closure_id ->
    /// captured `this` value and label). Folded into
    /// `closures_memory_bytes`, so the strict estimate==recompute invariant
    /// holds through the existing `apply_closures_memory_delta` pattern.
    pub(super) fn estimate_arrow_lexical_this_entry_bytes(entry: &(Value, Label)) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<u32>() as u64)
            .saturating_add(Self::estimate_value_bytes(&entry.0))
            .saturating_add(Self::estimate_label_bytes(&entry.1))
    }

    pub(super) fn registers_memory_bytes(&self) -> u64 {
        if let Some(bytes) = self.registers_value_bytes.get() {
            debug_assert_eq!(
                bytes,
                Self::saturating_sum(self.registers.iter().map(Self::estimate_value_bytes)),
                "cached register-file bytes went stale: a register write bypassed mutate_registers"
            );
            return bytes;
        }
        let bytes = Self::saturating_sum(self.registers.iter().map(Self::estimate_value_bytes));
        self.registers_value_bytes.set(Some(bytes));
        bytes
    }

    pub(super) fn register_labels_memory_bytes(&self) -> u64 {
        if let Some(bytes) = self.register_labels_bytes.get() {
            debug_assert_eq!(
                bytes,
                Self::saturating_sum(self.register_labels.iter().map(Self::estimate_label_bytes)),
                "cached register-label bytes went stale: a label write bypassed the cache"
            );
            return bytes;
        }
        let bytes =
            Self::saturating_sum(self.register_labels.iter().map(Self::estimate_label_bytes));
        self.register_labels_bytes.set(Some(bytes));
        bytes
    }

    /// Move the cached register-label bytes by a write the caller measured:
    /// labels of `released` bytes left the file and labels of `added` bytes
    /// entered it (the label file's [`Self::mutate_registers_by_bytes`]).
    pub(super) fn adjust_register_labels_bytes(&self, released: u64, added: u64) {
        self.register_labels_bytes.set(
            self.register_labels_bytes
                .get()
                .map(|bytes| bytes.saturating_sub(released).saturating_add(added)),
        );
    }

    /// Install a whole label file whose [`Self::register_labels_memory_bytes`]
    /// is `bytes` when the caller knows it (a Public file is 0, a restored
    /// snapshot carries its own), else `None`.
    pub(super) fn install_register_labels(&mut self, labels: Vec<Label>, bytes: Option<u64>) {
        self.note_registers_written_to(labels.len());
        self.all_register_labels_public = labels.iter().all(|label| matches!(label, Label::Public));
        self.register_labels = labels;
        self.register_labels_bytes.set(bytes);
    }

    pub(super) fn active_inline_callback_context_memory_bytes(&self) -> u64 {
        self.active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0)
    }

    pub(super) fn register_context_labels_memory_bytes(&self) -> u64 {
        self.register_labels_memory_bytes()
            .saturating_add(self.active_inline_callback_context_memory_bytes())
    }

    pub(super) fn heap_memory_bytes(&self) -> u64 {
        self.heap.estimated_bytes()
    }

    /// Structural bytes of the live scope chain plus the deduped payload of
    /// every shared binding cell across all accounted surfaces (bd-sblaq).
    /// Keeping the payload inside this component means every existing
    /// scope-bracketed delta (push/pop/declare/store/call-setup/restore)
    /// observes payload ownership changes exactly, including a popped frame
    /// whose cells survive through closure aliases.
    ///
    /// bd-9vouw.31: cells held by closures and suspended activations come from
    /// the incrementally maintained cold-cell ledger, as do those of the saved
    /// caller chains below the top call frame (bd-9vouw.72); only the live
    /// chain and the top frame's saved chain are walked. Equal to
    /// [`Self::scope_chain_memory_bytes_by_walk`] by construction; unit-test
    /// builds assert that on every call.
    ///
    /// bd-9vouw.154: the frame maps' key bytes are in this component too, each
    /// distinct map once (see [`Self::scope_chain_structural_bytes`]).
    pub(super) fn scope_chain_memory_bytes(&self) -> u64 {
        let bytes = self
            .scope_chain_structural_bytes()
            .saturating_add(self.closures.cold_cells.payload_bytes)
            .saturating_add(self.live_only_binding_cell_payload_bytes());
        #[cfg(test)]
        debug_assert_eq!(
            bytes,
            self.scope_chain_memory_bytes_by_walk(),
            "cold binding-cell ledger drifted from the full payload walk (bd-9vouw.31)"
        );
        bytes
    }

    /// Full-walk reference for [`Self::scope_chain_memory_bytes`], used by the
    /// `recompute_estimated_memory_bytes` oracle.
    pub(super) fn scope_chain_memory_bytes_by_walk(&self) -> u64 {
        Self::estimate_scope_chain_slot_bytes(&self.scope_chain.frames)
            .saturating_add(self.shared_frame_map_key_bytes())
            .saturating_add(self.shared_binding_cell_payloads_memory_bytes())
    }

    /// Key bytes of every frame map reachable from the accounted surfaces —
    /// the live chain, the call frames' saved caller chains, closure
    /// environments and suspended activations — each distinct map once,
    /// recomputed from its bindings (bd-9vouw.154). Full-walk oracle for the
    /// ledger's `map_key_bytes` plus [`Self::live_only_frame_map_key_bytes`].
    pub(super) fn shared_frame_map_key_bytes(&self) -> u64 {
        fn add(frames: &[ScopeFrame], seen: &mut BTreeSet<usize>, total: &mut u64) {
            for frame in frames {
                if seen.insert(ColdBindingCells::map_key(frame)) {
                    *total = total.saturating_add(InterpreterCore::saturating_sum(
                        frame
                            .bindings
                            .keys()
                            .map(|name| ScopeFrame::binding_key_bytes(name)),
                    ));
                }
            }
        }
        fn add_execution(
            execution: &GeneratorExecutionSnapshot,
            seen: &mut BTreeSet<usize>,
            total: &mut u64,
        ) {
            add(&execution.scope_chain.frames, seen, total);
            for frame in &execution.call_stack {
                if let Some(saved) = &frame.saved_scope_chain {
                    add(saved, seen, total);
                }
            }
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        add(&self.scope_chain.frames, &mut seen, &mut total);
        for frame in self.call_stack.iter() {
            if let Some(saved) = &frame.saved_scope_chain {
                add(saved, &mut seen, &mut total);
            }
        }
        for closure in self.closures.iter() {
            add(&closure.captured_env, &mut seen, &mut total);
        }
        for generator in self.generators.iter() {
            if let Some(execution) = &generator.execution {
                add_execution(execution, &mut seen, &mut total);
            }
        }
        for function in self.async_functions.iter() {
            if let Some(execution) = &function.isolated_execution {
                add_execution(execution, &mut seen, &mut total);
            }
        }
        total
    }

    /// Structural bytes of the scope component: the live chain's frame slots
    /// plus the key bytes of the frame maps, each distinct map once
    /// (bd-9vouw.154). The ledger charges the maps closures, suspended
    /// activations and the saved chains below the top call frame hold; the
    /// live chain and the top frame's saved chain add the maps it does not
    /// hold. O(depth): the ledger's total is kept current and a map's holder
    /// count is read from the map. Moving a map between the ledger and the
    /// live chain (a capture, a call, a return) leaves this total unchanged,
    /// so the scope-swap deltas stay structural.
    pub(super) fn scope_chain_structural_bytes(&self) -> u64 {
        Self::estimate_scope_chain_slot_bytes(&self.scope_chain.frames)
            .saturating_add(self.closures.cold_cells.map_key_bytes)
            .saturating_add(self.live_only_frame_map_key_bytes())
    }

    /// Key bytes of the frame maps on the live chain and the top call frame's
    /// saved chain that the cold-cell ledger does not hold, each distinct map
    /// once (bd-9vouw.154).
    pub(super) fn live_only_frame_map_key_bytes(&self) -> u64 {
        let cold = &self.closures.cold_cells;
        let live = &self.scope_chain.frames;
        let mut total = Self::saturating_sum(
            live.iter()
                .filter(|frame| !cold.holds_frame(frame))
                .map(|frame| frame.key_bytes),
        );
        if let Some(saved) = self.call_stack.top_saved_scope_chain() {
            total = total.saturating_add(Self::saturating_sum(
                saved
                    .iter()
                    .filter(|frame| !cold.holds_frame(frame) && !Self::chain_has_map(live, frame))
                    .map(|frame| frame.key_bytes),
            ));
        }
        total
    }

    /// Whether `frames` contains `frame`'s map.
    pub(super) fn chain_has_map(frames: &[ScopeFrame], frame: &ScopeFrame) -> bool {
        frames
            .iter()
            .any(|other| Rc::ptr_eq(&other.bindings, &frame.bindings))
    }

    /// Key bytes the live-only walk charged for a just-popped top frame's
    /// saved chain that nothing charges until that chain is restored: maps
    /// the ledger does not hold, on neither the live chain nor the new top
    /// frame's saved chain (bd-9vouw.154). A delta measured between the pop
    /// and the restore adds them to its starting point.
    pub(super) fn popped_frame_unwalked_map_key_bytes(&self, frame: &CallFrame) -> u64 {
        let Some(saved) = frame.saved_scope_chain.as_deref() else {
            return 0;
        };
        let cold = &self.closures.cold_cells;
        let top_saved = self.call_stack.top_saved_scope_chain().unwrap_or_default();
        Self::saturating_sum(
            saved
                .iter()
                .filter(|saved_frame| {
                    !cold.holds_frame(saved_frame)
                        && !Self::chain_has_map(&self.scope_chain.frames, saved_frame)
                        && !Self::chain_has_map(top_saved, saved_frame)
                })
                .map(|saved_frame| saved_frame.key_bytes),
        )
    }

    /// Payload of the cells reachable from the live scope chain or the top
    /// call frame's saved caller chain that no cold surface holds
    /// (bd-9vouw.31). The saved chains below the top frame are registered in
    /// the cold ledger by [`CallStack`] (bd-9vouw.72).
    pub(super) fn live_only_binding_cell_payload_bytes(&self) -> u64 {
        let cold = &self.closures.cold_cells;
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        let mut total = Self::accumulate_live_only_cell_payload_bytes(
            &self.scope_chain.frames,
            cold,
            &mut seen,
        );
        if let Some(saved) = self.call_stack.top_saved_scope_chain() {
            total = total.saturating_add(Self::accumulate_live_only_cell_payload_bytes(
                saved, cold, &mut seen,
            ));
        }
        total
    }

    pub(super) fn accumulate_live_only_cell_payload_bytes(
        frames: &[ScopeFrame],
        cold: &ColdBindingCells,
        seen: &mut BTreeSet<usize>,
    ) -> u64 {
        let mut total = 0u64;
        for frame in frames {
            // A held map's cells are all charged by the ledger; skipping it
            // keeps a call's accounting from visiting every global binding.
            if cold.holds_frame(frame) {
                continue;
            }
            for binding in frame.bindings.values() {
                if !cold.contains(&binding.state)
                    && seen.insert(Rc::as_ptr(&binding.state) as usize)
                {
                    total = total
                        .saturating_add(Self::estimate_binding_cell_payload_bytes(&binding.state));
                }
            }
        }
        total
    }

    pub(super) fn realm_dynamic_globals_memory_bytes(&self) -> u64 {
        Self::estimate_scope_bindings_bytes(&self.realm_dynamic_globals)
    }

    pub(super) fn estimate_generated_function_realm_globals_bytes(
        globals: &BTreeMap<String, ScopeBinding>,
    ) -> u64 {
        Self::estimate_scope_bindings_bytes(globals)
    }

    pub(super) fn generated_function_realm_globals_memory_bytes(&self) -> u64 {
        self.generated_function_realm_globals
            .as_ref()
            .map(Self::estimate_generated_function_realm_globals_bytes)
            .unwrap_or(0)
    }

    pub(super) fn estimate_generated_function_realm_scope_bytes(
        globals: &BTreeMap<String, ScopeBinding>,
    ) -> u64 {
        MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES
            .saturating_add(Self::estimate_scope_bindings_bytes(globals))
    }

    pub(super) fn runtime_name_references_memory_bytes(&self) -> u64 {
        Self::saturating_sum(self.runtime_name_references.iter().map(|reference| {
            let retained_value_bytes = match reference {
                RuntimeNameReference::Resolved(binding) => binding
                    .state
                    .try_borrow()
                    .map(|state| Self::estimate_value_bytes(&state.value))
                    .unwrap_or(u64::MAX),
                RuntimeNameReference::Unresolvable | RuntimeNameReference::RealmGlobal => 0,
            };
            (std::mem::size_of::<RuntimeNameReference>() as u64)
                .saturating_add(retained_value_bytes)
        }))
    }

    /// Closure-table component from the running totals kept by
    /// [`ClosureTable`] and each [`ClosureSideTable`] (bd-9vouw.31). Equal to
    /// [`Self::closures_memory_bytes_by_walk`] by construction; unit-test
    /// builds assert that on every call.
    pub(super) fn closures_memory_bytes(&self) -> u64 {
        let bytes = self
            .closures
            .structural_bytes()
            .saturating_add(self.closure_method_metadata.bytes())
            .saturating_add(self.closure_lexical_super_metadata.bytes())
            .saturating_add(self.arrow_lexical_this.bytes())
            .saturating_add(self.closure_module_origins.bytes())
            .saturating_add(self.closure_generated_function_artifacts.bytes())
            .saturating_add(self.runtime_name_references_memory_bytes());
        #[cfg(test)]
        debug_assert_eq!(
            bytes,
            self.closures_memory_bytes_by_walk(),
            "closure running totals drifted from the full walk (bd-9vouw.31)"
        );
        bytes
    }

    pub(super) fn estimate_closure_module_origin_entry_bytes(origin: &str) -> u64 {
        (std::mem::size_of::<u32>() as u64).saturating_add(Self::estimate_string_bytes(origin))
    }

    pub(super) fn estimate_closure_generated_function_artifact_entry_bytes() -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<u32>() as u64)
            .saturating_add(std::mem::size_of::<GeneratedFunctionArtifactHandle>() as u64)
    }

    /// Full-walk reference for [`Self::closures_memory_bytes`], used by the
    /// `recompute_estimated_memory_bytes` oracle.
    pub(super) fn closures_memory_bytes_by_walk(&self) -> u64 {
        Self::estimate_closures_bytes(self.closures.iter())
            .saturating_add(Self::saturating_sum(
                self.closure_method_metadata
                    .values()
                    .map(Self::estimate_closure_method_metadata_entry_bytes),
            ))
            .saturating_add(Self::saturating_sum(
                self.closure_lexical_super_metadata
                    .values()
                    .map(Self::estimate_closure_lexical_super_metadata_entry_bytes),
            ))
            .saturating_add(Self::saturating_sum(
                self.arrow_lexical_this
                    .values()
                    .map(Self::estimate_arrow_lexical_this_entry_bytes),
            ))
            .saturating_add(Self::saturating_sum(
                self.closure_module_origins.values().map(|origin| {
                    (std::mem::size_of::<u32>() as u64)
                        .saturating_add(Self::estimate_string_bytes(origin))
                }),
            ))
            .saturating_add(Self::saturating_sum(
                self.closure_generated_function_artifacts.values().map(|_| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(std::mem::size_of::<u32>() as u64)
                        .saturating_add(
                            std::mem::size_of::<GeneratedFunctionArtifactHandle>() as u64
                        )
                }),
            ))
            // Exact name References share the same mutable-cell accounting
            // problem as closures. Folding them into this component ensures
            // every existing scope/closure write delta observes value-size
            // changes while a Reference token retains the cell.
            .saturating_add(self.runtime_name_references_memory_bytes())
    }

    pub(super) fn call_stack_frame_memory_bytes(&self) -> u64 {
        let bytes = self.call_stack.frame_bytes();
        #[cfg(test)]
        debug_assert_eq!(
            bytes,
            Self::saturating_sum(
                self.call_stack
                    .iter()
                    .map(Self::estimate_live_call_frame_bytes)
            ),
            "call-stack running total drifted from the full walk (bd-9vouw.72)"
        );
        bytes
    }

    /// Call frames and the interpreter-level abrupt-completion slots are one
    /// ownership component. Throws/returns move between these stores during
    /// calls and finally unwinding; treating the transfer as a single delta
    /// prevents both transient double charging and silent release drift.
    pub(super) fn call_stack_memory_bytes(&self) -> u64 {
        self.call_stack_frame_memory_bytes()
            .saturating_add(self.abrupt_completion_memory_bytes())
    }

    pub(super) fn module_snapshot_call_stack_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.call_stack
                .iter()
                .map(Self::estimate_call_frame_snapshot_clone_bytes),
        )
        .saturating_add(self.abrupt_completion_memory_bytes())
    }

    pub(super) fn event_listeners_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.event_listeners
                .values()
                .flat_map(|by_event| by_event.iter())
                .flat_map(|(event, records)| {
                    records.iter().map(move |record| {
                        Self::estimate_event_listener_record_bytes(event, record)
                    })
                }),
        )
    }

    pub(super) fn event_once_wrappers_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.event_once_wrappers
                .values()
                .map(Self::estimate_event_once_wrapper_state_bytes),
        )
    }

    pub(super) fn event_promise_waiters_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.event_promise_waiters
                .values()
                .flat_map(|by_event| by_event.iter())
                .flat_map(|(event, records)| {
                    records.iter().map(move |record| {
                        Self::estimate_event_promise_waiter_record_bytes(
                            event,
                            &record.registration_label,
                        )
                    })
                }),
        )
    }

    pub(super) fn estimate_url_state_bytes(state: &UrlRuntimeState) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<UrlRuntimeState>() as u64)
            .saturating_add(Self::estimate_string_bytes(&state.href))
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn estimate_url_pair_storage_bytes(pairs: &[(String, String)]) -> u64 {
        u64::try_from(pairs.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<(String, String)>() as u64)
            .saturating_add(Self::saturating_sum(pairs.iter().flat_map(
                |(name, value)| {
                    [
                        Self::estimate_string_bytes(name),
                        Self::estimate_string_bytes(value),
                    ]
                },
            )))
    }

    pub(super) fn estimate_url_search_params_state_bytes(
        state: &UrlSearchParamsRuntimeState,
    ) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<UrlSearchParamsRuntimeState>() as u64)
            .saturating_add(Self::estimate_url_pair_storage_bytes(&state.pairs))
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn url_objects_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.url_objects
                .values()
                .map(Self::estimate_url_state_bytes),
        )
    }

    pub(super) fn url_search_params_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.url_search_params
                .values()
                .map(Self::estimate_url_search_params_state_bytes),
        )
    }

    pub(super) fn estimate_cluster_runtime_state_bytes(state: &ClusterRuntimeState) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<ClusterRuntimeState>() as u64)
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn cluster_facades_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.cluster_facades
                .values()
                .map(Self::estimate_cluster_runtime_state_bytes),
        )
    }

    pub(super) fn estimate_crypto_object_state_bytes(state: &CryptoObjectState) -> u64 {
        let dynamic_bytes = match state {
            CryptoObjectState::HashActive { input, .. } => input.capacity(),
            CryptoObjectState::HmacActive { key, input, .. } => {
                key.capacity().saturating_add(input.capacity())
            }
            CryptoObjectState::CipherActive {
                key,
                iv,
                input,
                auth_tag,
                output_encoding,
                output_remainder,
                ..
            } => key
                .capacity()
                .saturating_add(iv.capacity())
                .saturating_add(input.capacity())
                .saturating_add(auth_tag.as_ref().map_or(0, |tag| tag.capacity()))
                .saturating_add(output_encoding.as_ref().map_or(0, String::capacity))
                .saturating_add(output_remainder.capacity()),
            CryptoObjectState::CipherFinalized { auth_tag, .. } => {
                auth_tag.as_ref().map_or(0, |tag| tag.capacity())
            }
            CryptoObjectState::HashFinalized { .. } | CryptoObjectState::HmacFinalized { .. } => 0,
            CryptoObjectState::KeyPairActive {
                private_key,
                public_key,
                ..
            } => private_key.capacity().saturating_add(public_key.len()),
        };
        CRYPTO_STATE_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
            .saturating_add(u64::try_from(dynamic_bytes).unwrap_or(u64::MAX))
            .saturating_add(Self::estimate_label_bytes(state.lifecycle_label()))
    }

    pub(super) fn crypto_objects_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.crypto_objects
                .values()
                .map(Self::estimate_crypto_object_state_bytes),
        )
    }

    pub(super) fn readable_from_streams_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.readable_from_streams
                .values()
                .map(Self::estimate_readable_from_state_bytes),
        )
    }

    pub(super) fn readable_terminal_states_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.readable_terminal_states
                .values()
                .map(Self::estimate_readable_terminal_state_bytes),
        )
    }

    pub(super) fn readable_pipe_links_memory_bytes(&self) -> u64 {
        u64::try_from(
            self.readable_pipe_links
                .len()
                .saturating_add(self.readable_pipe_sources.len()),
        )
        .unwrap_or(u64::MAX)
        .saturating_mul(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
    }

    pub(super) fn writable_streams_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.writable_streams
                .values()
                .map(Self::recompute_writable_state_bytes),
        )
    }

    pub(super) fn stream_pipelines_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.stream_pipelines
                .values()
                .map(Self::stream_pipeline_state_bytes),
        )
    }

    pub(super) fn writable_terminal_states_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.writable_terminal_states
                .values()
                .map(Self::estimate_writable_terminal_state_bytes),
        )
    }

    pub(super) fn release_event_listener_memory(
        &mut self,
        event: &RuntimePropertyKey,
        record: &EventListenerRecord,
    ) {
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_event_listener_record_bytes(event, record));
    }

    /// Live (unreclaimed) heap objects: what the heap-object budget counts.
    pub(super) fn heap_object_count_u32(&self) -> u32 {
        u32::try_from(self.heap.live_len()).unwrap_or(u32::MAX)
    }

    #[inline]
    pub(super) fn memory_request_exceeds_budget(
        &self,
        requested_base_bytes: u64,
        max_bytes: u64,
    ) -> bool {
        let requested_bytes = self.total_memory_bytes_from_base(requested_base_bytes);
        // `u64::MAX` is the saturating overflow sentinel for logical memory
        // accounting. Admitting it would make a later subtraction lossy
        // (`MAX - MAX == 0`) and allow the incremental total to drift from
        // eager recomputation, even when the configured ceiling is unlimited.
        requested_bytes == u64::MAX
            || requested_bytes > max_bytes
            || self.sandbox_memory_request_exceeds_budget(requested_bytes)
            || self.sandbox_forbids_memory_growth(requested_base_bytes)
    }

    // Console retention has its own ordinary budget and is not part of the
    // legacy live-memory accumulator. Include it in the sandbox ceiling so
    // allowing Console cannot evade the narrowed allocation budget.
    fn sandbox_console_memory_bytes(&self) -> u64 {
        (self.console_output_bytes as u64)
            .saturating_add(
                (self.console_output.len() as u64)
                    .saturating_mul(std::mem::size_of::<ConsoleEntry>() as u64),
            )
            .saturating_add(
                (self
                    .console_counts
                    .len()
                    .saturating_add(self.console_timers.len()) as u64)
                    .saturating_mul(std::mem::size_of::<(String, u64)>() as u64),
            )
    }

    pub(super) fn sandbox_memory_usage(&self) -> u64 {
        self.estimated_memory_bytes()
            .saturating_add(self.sandbox_console_memory_bytes())
    }

    fn sandbox_memory_request_exceeds_budget(&self, requested_bytes: u64) -> bool {
        self.active_sandbox.get().is_some_and(|sandbox| {
            requested_bytes.saturating_add(self.sandbox_console_memory_bytes())
                > sandbox.memory_ceiling_bytes
        })
    }

    pub(super) fn check_sandbox_console_allocation(
        &self,
        added_bytes: u64,
    ) -> Result<(), InterpreterError> {
        if let Some(sandbox) = self.active_sandbox.get()
            && (self.config.sandbox_policy.max_memory_bytes == 0
                || self.sandbox_memory_usage().saturating_add(added_bytes)
                    > sandbox.memory_ceiling_bytes)
        {
            return Err(Self::sandbox_interruption());
        }
        Ok(())
    }

    pub(super) fn effective_memory_budget(&self, max_bytes: u64) -> u64 {
        self.active_sandbox.get().map_or(max_bytes, |sandbox| {
            max_bytes.min(sandbox.memory_ceiling_bytes)
        })
    }

    fn sandbox_forbids_memory_growth(&self, requested_base_bytes: u64) -> bool {
        self.active_sandbox.get().is_some()
            && self.config.sandbox_policy.max_memory_bytes == 0
            && requested_base_bytes > self.estimated_memory_bytes
    }

    /// Shared by every managed object allocator, including builtin buffer and
    /// view constructors that bypass instruction-level allocation hooks.
    pub(super) fn ensure_heap_allocation_allowed(&self) -> Result<(), InterpreterError> {
        if !self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::HeapAllocate)
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: "HeapAllocate".to_string(),
            });
        }
        if self.active_sandbox.get().is_some()
            && (self.config.sandbox_policy.max_memory_bytes == 0
                || !self
                    .config
                    .sandbox_policy
                    .allows_runtime_capability(RuntimeCapability::HeapAllocate))
        {
            return Err(Self::sandbox_interruption());
        }
        Ok(())
    }

    pub(super) fn memory_budget_error(
        &self,
        requested_base_bytes: u64,
        requested_heap_objects: u32,
    ) -> InterpreterError {
        let requested_bytes = self.total_memory_bytes_from_base(requested_base_bytes);
        if requested_heap_objects <= self.config.max_heap_objects
            && requested_bytes <= self.config.max_total_memory_bytes
            && (self.sandbox_memory_request_exceeds_budget(requested_bytes)
                || self.sandbox_forbids_memory_growth(requested_base_bytes))
        {
            return Self::sandbox_interruption();
        }
        InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes: self.effective_memory_budget(self.config.max_total_memory_bytes),
            requested_heap_objects,
            max_heap_objects: self.config.max_heap_objects,
        }
    }

    /// Eager reference for the incremental `estimated_memory_bytes` telemetry:
    /// walks the full register/heap/scope/closure/call-stack/iterator/generator
    /// state and re-derives the estimate from scratch with the same algebra the
    /// incremental accounting applies per write (PERF-H8). O(state size), so it
    /// is a validation surface, not a hot-path API: integration tests compare
    /// it against `estimated_memory_bytes()` to prove the incremental
    /// accumulator has not drifted (bd-o4cbn.13.4).
    ///
    /// bd-9vouw.31: this walks every closure environment, suspended
    /// activation, Promise record and replay-witness event for the scope,
    /// closure and Promise-runtime components, so it stays the independent
    /// oracle; runtime re-synchronization uses
    /// [`Self::recompute_base_estimated_memory_bytes`], which reads those
    /// components from their running totals.
    pub(super) fn recompute_base_estimated_memory_bytes_by_walk(&self) -> u64 {
        self.base_estimated_memory_bytes_with(MemoryComponents {
            heap: Self::saturating_sum(self.heap.iter().map(Self::estimate_heap_object_bytes)),
            async_functions: self.async_functions_memory_bytes_by_walk(),
            iterators: Self::saturating_sum(
                self.iterators.iter().map(Self::estimate_iterator_bytes),
            ),
            generators: Self::estimate_generators_bytes(self.generators.iter()),
            async_generators: self.async_generators_memory_bytes_by_walk(),
            scope_chain: self.scope_chain_memory_bytes_by_walk(),
            closures: self.closures_memory_bytes_by_walk(),
            promise_runtime: self.promise_runtime_memory_bytes_by_walk(),
        })
    }

    /// Runtime re-derivation of the base estimate. Identical algebra to
    /// [`Self::recompute_base_estimated_memory_bytes_by_walk`], with the
    /// heap, scope, closure and Promise-runtime components taken from their
    /// running totals (bd-9vouw.31). The heap total re-measures only objects
    /// borrowed mutably since the last derivation: re-walking the heap here
    /// made every resumed `await` O(heap), so an await loop was quadratic.
    pub(super) fn recompute_base_estimated_memory_bytes(&self) -> u64 {
        let heap_bytes = self.heap.estimated_bytes();
        #[cfg(test)]
        debug_assert_eq!(
            heap_bytes,
            Self::saturating_sum(self.heap.iter().map(Self::estimate_heap_object_bytes)),
            "heap running total drifted from the full walk"
        );
        let iterator_bytes = self.iterators.estimated_bytes();
        #[cfg(test)]
        debug_assert_eq!(
            iterator_bytes,
            Self::saturating_sum(self.iterators.iter().map(Self::estimate_iterator_bytes)),
            "iterator running total drifted from the full walk"
        );
        let generator_bytes = self.generators.estimated_bytes();
        #[cfg(test)]
        debug_assert_eq!(
            generator_bytes,
            Self::estimate_generators_bytes(self.generators.iter()),
            "generator running total drifted from the full walk"
        );
        let async_generator_bytes = self.async_generators_memory_bytes();
        #[cfg(test)]
        debug_assert_eq!(
            async_generator_bytes,
            self.async_generators_memory_bytes_by_walk(),
            "async generator running total drifted from the full walk"
        );
        self.base_estimated_memory_bytes_with(MemoryComponents {
            heap: heap_bytes,
            async_functions: self.async_functions_memory_bytes(),
            iterators: iterator_bytes,
            generators: generator_bytes,
            async_generators: async_generator_bytes,
            scope_chain: self.scope_chain_memory_bytes(),
            closures: self.closures_memory_bytes(),
            promise_runtime: self.promise_runtime_memory_bytes(),
        })
    }

    pub(super) fn base_estimated_memory_bytes_with(&self, components: MemoryComponents) -> u64 {
        let MemoryComponents {
            heap: heap_bytes,
            async_functions: async_function_bytes,
            iterators: iterator_bytes,
            generators: generator_bytes,
            async_generators: async_generator_bytes,
            scope_chain: scope_chain_bytes,
            closures: closure_bytes,
            promise_runtime: promise_runtime_bytes,
        } = components;
        self.symbol_state_memory_bytes()
            .saturating_add(heap_bytes)
            .saturating_add(Self::saturating_sum(
                self.registers.iter().map(Self::estimate_value_bytes),
            ))
            .saturating_add(self.register_context_labels_memory_bytes())
            .saturating_add(scope_chain_bytes)
            .saturating_add(self.mapped_argument_bindings_memory_bytes())
            .saturating_add(self.realm_dynamic_globals_memory_bytes())
            .saturating_add(self.generated_function_realm_globals_memory_bytes())
            .saturating_add(closure_bytes)
            .saturating_add(self.call_stack_memory_bytes())
            .saturating_add(iterator_bytes)
            .saturating_add(generator_bytes)
            .saturating_add(self.generator_delegation_memory_bytes())
            .saturating_add(async_function_bytes)
            .saturating_add(async_generator_bytes)
            .saturating_add(self.top_level_await_outcome_memory_bytes())
            .saturating_add(self.pending_io_callbacks_memory_bytes())
            .saturating_add(self.pending_fs_promise_reads_memory_bytes())
            .saturating_add(self.pending_dynamic_imports_memory_bytes())
            .saturating_add(self.deferred_callback_in_flight_bytes)
            .saturating_add(self.pending_child_process_tasks_memory_bytes())
            .saturating_add(self.child_process_task_in_flight_bytes)
            .saturating_add(self.completed_child_processes_memory_bytes())
            .saturating_add(self.child_process_streams_memory_bytes())
            .saturating_add(self.child_process_handles_memory_bytes())
            .saturating_add(self.pending_timer_tasks_memory_bytes())
            .saturating_add(self.atomics_async_waiters_memory_bytes())
            .saturating_add(promise_runtime_bytes)
            .saturating_add(self.promise_reaction_callables_memory_bytes())
            .saturating_add(self.promise_value_carriers_memory_bytes())
            .saturating_add(self.next_tick_queue_memory_bytes())
            .saturating_add(self.weakmap_storage_memory_bytes())
            .saturating_add(self.event_listeners_memory_bytes())
            .saturating_add(self.event_once_wrappers_memory_bytes())
            .saturating_add(self.event_promise_waiters_memory_bytes())
            .saturating_add(self.object_mutation_labels_memory_bytes())
            .saturating_add(self.url_objects_memory_bytes())
            .saturating_add(self.url_search_params_memory_bytes())
            .saturating_add(self.cluster_facades_memory_bytes())
            .saturating_add(self.crypto_objects_memory_bytes())
            .saturating_add(self.stream_pipelines_memory_bytes())
            .saturating_add(self.readable_from_streams_memory_bytes())
            .saturating_add(self.readable_terminal_states_memory_bytes())
            .saturating_add(self.pending_readable_pumps_memory_bytes())
            .saturating_add(self.readable_pump_reservations_memory_bytes())
            .saturating_add(self.readable_pipe_links_memory_bytes())
            .saturating_add(self.loopback_servers_memory_bytes())
            .saturating_add(self.loopback_sockets_memory_bytes())
            .saturating_add(self.loopback_ports_memory_bytes())
            .saturating_add(self.pending_loopback_tasks_memory_bytes())
            .saturating_add(self.loopback_task_in_flight_bytes)
            .saturating_add(self.http_runtime_memory_bytes())
            .saturating_add(self.writable_streams_memory_bytes())
            .saturating_add(self.writable_terminal_states_memory_bytes())
            .saturating_add(self.writable_in_flight_callback_bytes)
            .saturating_add(self.module_state.retained_program_bytes)
            .saturating_add(self.module_state.retained_generated_function_bytes)
            .saturating_add(self.generated_code_observability_memory_bytes())
            .saturating_add(self.general_interpreter_events_memory_bytes())
            .saturating_add(self.generated_code_observability_reservation_bytes)
            .saturating_add(self.module_exports_memory_bytes())
            .saturating_add(self.state_capture_memory_bytes())
            .saturating_add(self.module_snapshot_in_flight_bytes)
            .saturating_add(self.temporarily_suspended_execution_bytes)
    }

    pub fn recompute_estimated_memory_bytes(&self) -> u64 {
        self.total_memory_bytes_from_base(self.recompute_base_estimated_memory_bytes_by_walk())
    }

    pub(super) fn sync_estimated_memory_bytes(&mut self) -> Result<u64, InterpreterError> {
        self.all_register_labels_public = self
            .register_labels
            .iter()
            .all(|label| matches!(label, Label::Public));
        let requested_bytes = self.recompute_base_estimated_memory_bytes();
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.estimated_memory_bytes = requested_bytes;
        Ok(self.total_memory_bytes_from_base(requested_bytes))
    }

    pub(super) fn apply_memory_component_delta(
        &mut self,
        previous_component_bytes: u64,
        next_component_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_component_bytes)
            .saturating_add(next_component_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.estimated_memory_bytes = requested_bytes;
        Ok(requested_bytes)
    }

    /// Charge a value/label write to one binding cell resolved through the
    /// live scope chain (bd-9vouw.31). Each distinct cell's payload is counted
    /// exactly once, by the cold-cell ledger (the caller refreshes it) or by
    /// the live-only walk, and the write changes no other component, so the
    /// delta is the cell's own payload change. Re-walking every live binding
    /// before and after made each scoped store O(bindings): with 2000
    /// top-level bindings, 20k calls of `s = add(s, i)` took 8.3 s.
    pub(super) fn apply_scope_cell_write_delta(
        &mut self,
        previous_payload_bytes: u64,
        cell: &Rc<RefCell<ScopeBindingState>>,
    ) -> Result<u64, InterpreterError> {
        if !self.mapped_argument_aliases.is_empty()
            && let Some(&(object_id, index)) = self
                .mapped_argument_aliases
                .get(&ColdBindingCells::key(cell))
        {
            return self.publish_mapped_argument_cell(
                object_id,
                index,
                previous_payload_bytes,
                cell,
            );
        }
        self.apply_memory_component_delta(
            previous_payload_bytes,
            Self::estimate_binding_cell_payload_bytes(cell),
        )
    }

    /// Payload of the cells a returning callee's chain held that are
    /// charged by nothing once the caller's chain is back (bd-9vouw.31).
    /// Frames still on the restored chain are skipped by identity. Captured
    /// cells stay in the cold ledger. What remains are the cells of frames
    /// the callee pushed, which nothing else reaches.
    pub(super) fn released_frame_cell_payload_bytes(&self, callee_frames: &[ScopeFrame]) -> u64 {
        let cold = &self.closures.cold_cells;
        // The cells counted so far. Every return runs this and most release
        // a few cells, so the first ones are kept on the stack and a set
        // takes the rest: no allocation for a small frame (bd-9vouw.504).
        let mut recent = [std::ptr::null::<RefCell<ScopeBindingState>>(); 8];
        let mut recent_len = 0;
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for frame in callee_frames {
            // A held map's cells are all still charged by the cold ledger.
            // As in the live-only walk, skip the map rather than looking up
            // each of its captured bindings again on every return.
            if cold.holds_frame(frame) {
                continue;
            }
            if self
                .scope_chain
                .frames
                .iter()
                .any(|restored| Rc::ptr_eq(&restored.bindings, &frame.bindings))
            {
                continue;
            }
            for binding in frame.bindings.values() {
                if cold.contains(&binding.state) {
                    continue;
                }
                let cell = Rc::as_ptr(&binding.state);
                let first_sight = if recent[..recent_len].contains(&cell) || seen.contains(&cell) {
                    false
                } else if recent_len < recent.len() {
                    recent[recent_len] = cell;
                    recent_len += 1;
                    true
                } else {
                    seen.insert(cell)
                };
                if first_sight {
                    total = total
                        .saturating_add(Self::estimate_binding_cell_payload_bytes(&binding.state));
                }
            }
        }
        total
    }

    /// Apply a scope/closure/call-stack delta whose scope side is already
    /// known: `previous_scope_bytes` holds the structural bytes before the
    /// change plus any payload it released.
    pub(super) fn apply_structural_scope_closure_call_stack_memory_delta(
        &mut self,
        previous_scope_bytes: u64,
        previous_closure_bytes: u64,
        previous_call_stack_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        self.apply_memory_component_delta(
            previous_scope_bytes
                .saturating_add(previous_closure_bytes)
                .saturating_add(previous_call_stack_bytes),
            self.scope_chain_structural_bytes()
                .saturating_add(self.closures_memory_bytes())
                .saturating_add(self.call_stack_memory_bytes()),
        )
    }

    /// A chain swap's structural delta minus the payload it released equals
    /// the full-walk scope delta.
    #[cfg(debug_assertions)]
    pub(super) fn debug_assert_scope_swap_delta(
        &self,
        walked_before: u64,
        structural_before: u64,
        released_payload_bytes: u64,
    ) {
        debug_assert_eq!(
            i128::from(self.scope_chain_memory_bytes()) - i128::from(walked_before),
            i128::from(self.scope_chain_structural_bytes())
                - i128::from(structural_before)
                - i128::from(released_payload_bytes),
            "a call or return must change scope memory by its structural delta \
             less the payload of the frames it released"
        );
    }

    /// Scope, closure and call-stack components by full walk: the total a
    /// scoped store used to diff before and after itself. Debug builds check
    /// every local delta against it.
    #[cfg(debug_assertions)]
    pub(super) fn scope_closure_call_stack_memory_bytes(&self) -> u64 {
        self.scope_chain_memory_bytes()
            .saturating_add(self.closures_memory_bytes())
            .saturating_add(self.call_stack_memory_bytes())
    }

    /// The cell-local delta equals the full-walk delta it replaced.
    #[cfg(debug_assertions)]
    pub(super) fn debug_assert_cell_write_delta(
        &self,
        walked_before: u64,
        previous_payload_bytes: u64,
        cell: &Rc<RefCell<ScopeBindingState>>,
    ) {
        let walked_after = self.scope_closure_call_stack_memory_bytes();
        let next_payload_bytes = Self::estimate_binding_cell_payload_bytes(cell);
        debug_assert_eq!(
            i128::from(walked_after) - i128::from(walked_before),
            i128::from(next_payload_bytes) - i128::from(previous_payload_bytes),
            "a scoped cell write must change memory by exactly its own payload delta"
        );
    }

    pub(super) fn apply_scope_chain_memory_delta(
        &mut self,
        previous_scope_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        self.apply_memory_component_delta(previous_scope_bytes, self.scope_chain_memory_bytes())
    }

    pub(super) fn apply_closures_memory_delta(
        &mut self,
        previous_closure_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        self.apply_memory_component_delta(previous_closure_bytes, self.closures_memory_bytes())
    }

    pub(super) fn apply_promise_runtime_memory_delta(
        &mut self,
        previous_promise_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        let next_promise_bytes = self.promise_runtime_memory_bytes();
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)
    }

    /// A Promise operation that charged its projected bytes before mutating
    /// (so the budget check stays ahead of every allocation) re-charges the
    /// actual size once it has run. The projection counts each witness event
    /// the operation appends, but a witness log that reaches twice its
    /// retained length drops its oldest 1,024 events on that push
    /// (bd-9vouw.71), so the runtime can end 64 KiB below the projection.
    /// Async resumptions account by deltas (bd-j9r60), so nothing else
    /// re-derives the estimate between these operations: without this the
    /// over-charge grew by 64 KiB per eviction until a 24,000-await loop
    /// failed a 2 MiB budget.
    pub(super) fn settle_projected_promise_bytes(
        &mut self,
        projected_promise_bytes: u64,
    ) -> Result<(), InterpreterError> {
        let actual_promise_bytes = self.promise_runtime_memory_bytes();
        self.apply_memory_component_delta(projected_promise_bytes, actual_promise_bytes)
            .map(|_| ())
    }

    pub(super) fn apply_scope_closure_call_stack_memory_delta(
        &mut self,
        previous_scope_bytes: u64,
        previous_closure_bytes: u64,
        previous_call_stack_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        self.apply_memory_component_delta(
            previous_scope_bytes
                .saturating_add(previous_closure_bytes)
                .saturating_add(previous_call_stack_bytes),
            self.scope_chain_memory_bytes()
                .saturating_add(self.closures_memory_bytes())
                .saturating_add(self.call_stack_memory_bytes()),
        )
    }

    pub(super) fn apply_call_stack_memory_delta(
        &mut self,
        previous_call_stack_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        self.apply_memory_component_delta(previous_call_stack_bytes, self.call_stack_memory_bytes())
    }

    pub(super) fn apply_scope_closure_call_stack_realm_memory_delta(
        &mut self,
        previous_scope_bytes: u64,
        previous_closure_bytes: u64,
        previous_call_stack_bytes: u64,
        previous_realm_global_bytes: u64,
        previous_generated_realm_global_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        self.apply_memory_component_delta(
            previous_scope_bytes
                .saturating_add(previous_closure_bytes)
                .saturating_add(previous_call_stack_bytes)
                .saturating_add(previous_realm_global_bytes)
                .saturating_add(previous_generated_realm_global_bytes),
            self.scope_chain_memory_bytes()
                .saturating_add(self.closures_memory_bytes())
                .saturating_add(self.call_stack_memory_bytes())
                .saturating_add(self.realm_dynamic_globals_memory_bytes())
                .saturating_add(self.generated_function_realm_globals_memory_bytes()),
        )
    }

    pub(super) fn apply_register_context_scope_call_stack_memory_delta(
        &mut self,
        previous_register_bytes: u64,
        previous_register_context_label_bytes: u64,
        previous_scope_bytes: u64,
        previous_call_stack_bytes: u64,
    ) -> Result<u64, InterpreterError> {
        self.apply_memory_component_delta(
            previous_register_bytes
                .saturating_add(previous_register_context_label_bytes)
                .saturating_add(previous_scope_bytes)
                .saturating_add(previous_call_stack_bytes),
            self.registers_memory_bytes()
                .saturating_add(self.register_context_labels_memory_bytes())
                .saturating_add(self.scope_chain_memory_bytes())
                .saturating_add(self.call_stack_memory_bytes()),
        )
    }

    pub(super) fn check_temporary_memory_budget(
        &self,
        temporary_bytes: u64,
    ) -> Result<(), InterpreterError> {
        let requested_bytes = self.estimated_memory_bytes.saturating_add(temporary_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        Ok(())
    }

    pub(super) fn clone_scope_frames_with_budget(
        &self,
        frames: &[ScopeFrame],
    ) -> Result<Vec<ScopeFrame>, InterpreterError> {
        self.clone_scope_frames_with_temporary_budget(frames, 0)
    }

    pub(super) fn clone_scope_frames_with_temporary_budget(
        &self,
        frames: &[ScopeFrame],
        temporary_bytes: u64,
    ) -> Result<Vec<ScopeFrame>, InterpreterError> {
        self.check_temporary_memory_budget(
            temporary_bytes.saturating_add(Self::estimate_scope_chain_bytes(frames)),
        )?;
        Ok(frames.to_vec())
    }

    pub(super) fn snapshot_scope_chain(&self) -> Result<Vec<ScopeFrame>, InterpreterError> {
        self.snapshot_scope_chain_with_temporary_budget(0)
    }

    pub(super) fn snapshot_scope_chain_with_temporary_budget(
        &self,
        temporary_bytes: u64,
    ) -> Result<Vec<ScopeFrame>, InterpreterError> {
        self.preflight_scope_chain_snapshot_with_temporary_budget(temporary_bytes)?;
        Ok(self.scope_chain.snapshot())
    }

    pub(super) fn preflight_scope_chain_snapshot_with_temporary_budget(
        &self,
        temporary_bytes: u64,
    ) -> Result<(), InterpreterError> {
        self.check_temporary_memory_budget(
            temporary_bytes
                .saturating_add(Self::estimate_scope_chain_bytes(&self.scope_chain.frames)),
        )
    }

    pub(super) fn rollback_call_setup_state(&mut self) {
        if let Some(frame) = self.call_stack.pop(&mut self.closures.cold_cells) {
            let depth = self.call_stack.len();
            self.pc_label_stack.retain(|pc| pc.call_depth <= depth);
            self.pending_exception = frame.saved_pending_exception;
            self.pending_exception_label = frame.saved_pending_exception_label;
            self.pending_return = frame.saved_pending_return;
            self.suspended_abrupt_completions
                .truncate(frame.saved_suspended_abrupt_depth);
            self.finally_frames.truncate(frame.saved_finally_mode_depth);
            if frame.scope_inert_virtual_scope_bytes > 0 {
                while self.scope_chain.depth() > frame.saved_scope_depth {
                    self.scope_chain.pop();
                }
            } else if let Some(saved) = frame.saved_scope_chain {
                self.scope_chain.frames = saved;
            } else {
                while self.scope_chain.depth() > frame.saved_scope_depth {
                    self.scope_chain.pop();
                }
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn rollback_call_setup(&mut self) {
        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let previous_closure_bytes = self.closures_memory_bytes();
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        self.rollback_call_setup_state();
        let previous_component_bytes = previous_scope_bytes
            .saturating_add(previous_closure_bytes)
            .saturating_add(previous_call_stack_bytes);
        let next_component_bytes = self
            .scope_chain_memory_bytes()
            .saturating_add(self.closures_memory_bytes())
            .saturating_add(self.call_stack_memory_bytes());
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_component_bytes)
            .saturating_add(next_component_bytes);
    }

    pub(super) fn alloc_array_buffer_object(
        &mut self,
        byte_length: usize,
    ) -> Result<ObjectId, InterpreterError> {
        self.alloc_buffer_object(byte_length, false)
    }

    /// A zeroed ArrayBuffer, or with `shared` a SharedArrayBuffer (ES2020
    /// 24.2.1.1 AllocateSharedArrayBuffer, bd-9vouw.244). Both hold their
    /// bytes in `array_buffer`, so typed arrays and DataViews view either;
    /// the brand and prototype tell them apart. One agent runs, so a
    /// SharedArrayBuffer's bytes are never shared with another thread.
    pub(super) fn alloc_buffer_object(
        &mut self,
        byte_length: usize,
        shared: bool,
    ) -> Result<ObjectId, InterpreterError> {
        let constructor = if shared {
            "SharedArrayBuffer"
        } else {
            "ArrayBuffer"
        };
        self.ensure_heap_allocation_allowed()?;

        let byte_length_u64 = u64::try_from(byte_length).map_err(|_| InterpreterError::RangeError {
            message: format!(
                "ArrayBuffer byteLength {byte_length} exceeds host addressable size; per-buffer cap is {} bytes, total cap is {} bytes, committed bytes are {}",
                MAX_ARRAY_BUFFER_BYTE_LENGTH,
                self.config.max_total_memory_bytes,
                self.estimated_memory_bytes(),
            ),
        })?;
        let byte_length_i64 = i64::try_from(byte_length).map_err(|_| InterpreterError::RangeError {
            message: format!(
                "ArrayBuffer byteLength {byte_length} exceeds JS integer storage; per-buffer cap is {} bytes, total cap is {} bytes, committed bytes are {}",
                MAX_ARRAY_BUFFER_BYTE_LENGTH,
                self.config.max_total_memory_bytes,
                self.estimated_memory_bytes(),
            ),
        })?;

        // Every ArrayBuffer (constructed, a view's `.buffer`, a slice) inherits
        // from %ArrayBuffer.prototype%: `instanceof ArrayBuffer`, `constructor`
        // and the prototype's methods. Materialized before the buffer's id is
        // taken, since the first call allocates the prototype object.
        let prototype = self.ensure_builtin_prototype(constructor)?;
        let requested_heap_objects = self.heap_object_count_u32().saturating_add(1);
        if requested_heap_objects > self.config.max_heap_objects {
            return Err(
                self.memory_budget_error(self.estimated_memory_bytes, requested_heap_objects)
            );
        }

        let id =
            ObjectId(
                u32::try_from(self.heap.len()).map_err(|_| InterpreterError::TypeError {
                    expected: "heap capacity".into(),
                    got: format!("exceeded u32::MAX ({})", self.heap.len()),
                })?,
            );

        let mut object = HeapObject::new();
        object.prototype = Some(prototype);
        object.brand = Some(Box::new(JsString::from(constructor)));
        object
            .properties
            .insert("byteLength".to_string(), Value::Int(byte_length_i64));

        let metadata_size = Self::estimate_heap_object_bytes(&object);
        let object_size = metadata_size.saturating_add(byte_length_u64);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(object_size);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, requested_heap_objects));
        }

        object.array_buffer = Some(Box::new(ArrayBufferBacking::new_zeroed(byte_length)));
        self.mutate_heap(|h| h.push(object));
        self.estimated_memory_bytes = requested_bytes;

        if let Some(profiler) = &mut self.profiling_data {
            profiler.record_object_allocation(object_size);
        }

        Ok(id)
    }

    pub(crate) fn with_array_buffer_bytes<R>(
        &self,
        object_id: ObjectId,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, InterpreterError> {
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let backing = object
            .array_buffer
            .as_ref()
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "ArrayBuffer".to_string(),
                got: object.brand().unwrap_or("object").to_string(),
            })?;
        Ok(f(&backing.bytes))
    }

    pub(crate) fn with_array_buffer_bytes_mut<R>(
        &mut self,
        object_id: ObjectId,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, InterpreterError> {
        self.mutate_heap(|heap| {
            let object = heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let got = object.brand().unwrap_or("object").to_string();
            let backing =
                object
                    .array_buffer
                    .as_mut()
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "ArrayBuffer".to_string(),
                        got,
                    })?;
            Ok(f(&mut backing.bytes))
        })
    }

    pub(super) fn alloc_typed_array_view_object(
        &mut self,
        kind: TypedArrayKind,
        buffer: ObjectId,
        byte_offset: usize,
        byte_length: usize,
        length: usize,
    ) -> Result<ObjectId, InterpreterError> {
        self.alloc_typed_array_view_object_with_buffer_identity(
            kind,
            buffer,
            byte_offset,
            byte_length,
            length,
            false,
        )
    }

    pub(super) fn alloc_typed_array_view_object_with_buffer_identity(
        &mut self,
        kind: TypedArrayKind,
        buffer: ObjectId,
        byte_offset: usize,
        byte_length: usize,
        length: usize,
        is_buffer: bool,
    ) -> Result<ObjectId, InterpreterError> {
        self.ensure_heap_allocation_allowed()?;

        let length_i64 = i64::try_from(length).map_err(|_| InterpreterError::RangeError {
            message: format!(
                "{} length {length} exceeds JS integer storage",
                kind.type_name()
            ),
        })?;
        let byte_length_i64 =
            i64::try_from(byte_length).map_err(|_| InterpreterError::RangeError {
                message: format!(
                    "{} byteLength {byte_length} exceeds JS integer storage",
                    kind.type_name(),
                ),
            })?;
        let byte_offset_i64 =
            i64::try_from(byte_offset).map_err(|_| InterpreterError::RangeError {
                message: format!(
                    "{} byteOffset {byte_offset} exceeds JS integer storage",
                    kind.type_name(),
                ),
            })?;
        let element_size_i64 = i64::try_from(kind.element_size()).expect("element size fits i64");
        // ES2020 22.2.4.2.1 AllocateTypedArray: a view inherits from its
        // constructor's prototype (which inherits %TypedArray.prototype%),
        // so `instanceof`, `constructor` and Object.getPrototypeOf see its
        // class. Unlinked, every typed array reported Object. Materialized
        // before the view's id is taken, since the first use allocates the
        // prototype objects. A Buffer inherits from Buffer.prototype, whose
        // own methods shadow the typed array ones (bd-9vouw.104).
        let prototype = Some(self.ensure_builtin_prototype(if is_buffer {
            "Buffer"
        } else {
            kind.type_name()
        })?);

        let requested_heap_objects = self.heap_object_count_u32().saturating_add(1);
        if requested_heap_objects > self.config.max_heap_objects {
            return Err(
                self.memory_budget_error(self.estimated_memory_bytes, requested_heap_objects)
            );
        }

        let id =
            ObjectId(
                u32::try_from(self.heap.len()).map_err(|_| InterpreterError::TypeError {
                    expected: "heap capacity".into(),
                    got: format!("exceeded u32::MAX ({})", self.heap.len()),
                })?,
            );

        let mut object = HeapObject::new();
        object.prototype = prototype;
        object.brand = Some(Box::new(JsString::from(kind.type_name())));
        object
            .properties
            .insert("__typedArrayKind".to_string(), Value::str(kind.type_name()));
        object
            .properties
            .insert("length".to_string(), Value::Int(length_i64));
        object
            .properties
            .insert("byteLength".to_string(), Value::Int(byte_length_i64));
        object
            .properties
            .insert("byteOffset".to_string(), Value::Int(byte_offset_i64));
        object
            .properties
            .insert("buffer".to_string(), Value::Object(buffer));
        object.properties.insert(
            "BYTES_PER_ELEMENT".to_string(),
            Value::Int(element_size_i64),
        );
        object.typed_array = Some(Box::new(TypedArrayView {
            kind,
            buffer,
            byte_offset,
            byte_length,
            length,
            is_buffer,
            bounds: None,
        }));

        let object_size = Self::estimate_heap_object_bytes(&object);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(object_size);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, requested_heap_objects));
        }

        self.mutate_heap(|h| h.push(object));
        self.estimated_memory_bytes = requested_bytes;

        if let Some(profiler) = &mut self.profiling_data {
            profiler.record_object_allocation(object_size);
        }

        Ok(id)
    }

    pub(super) fn alloc_buffer_view_object(
        &mut self,
        buffer: ObjectId,
        byte_offset: usize,
        byte_length: usize,
    ) -> Result<ObjectId, InterpreterError> {
        self.alloc_typed_array_view_object_with_buffer_identity(
            TypedArrayKind::Uint8,
            buffer,
            byte_offset,
            byte_length,
            byte_length,
            true,
        )
    }

    pub(super) fn alloc_fresh_buffer_object(
        &mut self,
        byte_length: usize,
        contents: Option<&[u8]>,
        temporary_bytes: usize,
    ) -> Result<ObjectId, InterpreterError> {
        self.checked_typed_array_byte_length(TypedArrayKind::Uint8, byte_length)?;
        if contents.is_some_and(|bytes| bytes.len() != byte_length) {
            return Err(InterpreterError::RangeError {
                message: "Buffer contents length does not match requested allocation".to_string(),
            });
        }
        self.ensure_heap_allocation_allowed()?;
        // Materialized before the heap indices below are taken: the first
        // use allocates the prototype objects (bd-9vouw.104). A refusal below
        // takes them back with the pair.
        let checkpoint = (self.heap.len(), self.estimated_memory_bytes);
        let prototypes = self
            .ensure_builtin_prototype("Buffer")
            .and_then(|view| Ok((view, self.ensure_builtin_prototype("ArrayBuffer")?)));
        let (view_prototype, buffer_prototype) = match prototypes {
            Ok(prototypes) => prototypes,
            Err(error) => {
                self.rollback_heap_and_new_prototypes(checkpoint.0, checkpoint.1);
                return Err(error);
            }
        };

        let byte_length_i64 =
            i64::try_from(byte_length).map_err(|_| InterpreterError::RangeError {
                message: format!("Buffer length {byte_length} exceeds JS integer storage"),
            })?;
        let buffer_index = self.heap.len();
        let view_index =
            buffer_index
                .checked_add(1)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "heap capacity".to_string(),
                    got: "Buffer allocation object index overflow".to_string(),
                })?;
        let buffer_id =
            ObjectId(
                u32::try_from(buffer_index).map_err(|_| InterpreterError::TypeError {
                    expected: "heap capacity".to_string(),
                    got: format!("exceeded u32::MAX ({buffer_index})"),
                })?,
            );
        let view_id =
            ObjectId(
                u32::try_from(view_index).map_err(|_| InterpreterError::TypeError {
                    expected: "heap capacity".to_string(),
                    got: format!("exceeded u32::MAX ({view_index})"),
                })?,
            );
        let requested_heap_objects = self.heap_object_count_u32().saturating_add(2);
        if requested_heap_objects > self.config.max_heap_objects {
            let error =
                self.memory_budget_error(self.estimated_memory_bytes, requested_heap_objects);
            self.rollback_heap_and_new_prototypes(checkpoint.0, checkpoint.1);
            return Err(error);
        }

        // Build both metadata records without allocating backing bytes. The
        // budget preflight below includes the final backing, view, and every
        // caller-declared live temporary. Only after it succeeds are either
        // heap object and the backing Vec published.
        let mut buffer_object = HeapObject::new();
        buffer_object.brand = Some(Box::new(JsString::from("ArrayBuffer")));
        buffer_object.prototype = Some(buffer_prototype);
        buffer_object
            .properties
            .insert("byteLength".to_string(), Value::Int(byte_length_i64));

        let mut view_object = HeapObject::new();
        view_object.brand = Some(Box::new(JsString::from("Uint8Array")));
        view_object.prototype = Some(view_prototype);
        view_object
            .properties
            .insert("__typedArrayKind".to_string(), Value::str("Uint8Array"));
        view_object
            .properties
            .insert("length".to_string(), Value::Int(byte_length_i64));
        view_object
            .properties
            .insert("byteLength".to_string(), Value::Int(byte_length_i64));
        view_object
            .properties
            .insert("byteOffset".to_string(), Value::Int(0));
        view_object
            .properties
            .insert("buffer".to_string(), Value::Object(buffer_id));
        view_object
            .properties
            .insert("BYTES_PER_ELEMENT".to_string(), Value::Int(1));
        view_object.typed_array = Some(Box::new(TypedArrayView {
            kind: TypedArrayKind::Uint8,
            buffer: buffer_id,
            byte_offset: 0,
            byte_length,
            length: byte_length,
            is_buffer: true,
            bounds: None,
        }));

        let backing_bytes =
            u64::try_from(byte_length).map_err(|_| InterpreterError::RangeError {
                message: "Buffer backing length exceeds memory accounting range".to_string(),
            })?;
        let temporary_bytes =
            u64::try_from(temporary_bytes).map_err(|_| InterpreterError::RangeError {
                message: "Buffer temporary length exceeds memory accounting range".to_string(),
            })?;
        let buffer_object_size =
            Self::estimate_heap_object_bytes(&buffer_object).saturating_add(backing_bytes);
        let view_object_size = Self::estimate_heap_object_bytes(&view_object);
        let committed_bytes = buffer_object_size.saturating_add(view_object_size);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(temporary_bytes)
            .saturating_add(committed_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            let error = self.memory_budget_error(requested_bytes, requested_heap_objects);
            self.rollback_heap_and_new_prototypes(checkpoint.0, checkpoint.1);
            return Err(error);
        }

        buffer_object.array_buffer = Some(Box::new(match contents {
            Some(bytes) => ArrayBufferBacking::with_bytes(bytes.to_vec()),
            None => ArrayBufferBacking::new_zeroed(byte_length),
        }));
        self.mutate_heap(|heap| {
            heap.push(buffer_object);
            heap.push(view_object);
        });
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(committed_bytes);
        if let Some(profiler) = &mut self.profiling_data {
            profiler.record_object_allocation(buffer_object_size);
            profiler.record_object_allocation(view_object_size);
        }
        Ok(view_id)
    }

    pub(super) fn alloc_buffer_from_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<ObjectId, InterpreterError> {
        self.alloc_fresh_buffer_object(bytes.len(), Some(bytes), bytes.len())
    }

    pub(super) fn alloc_buffer_from_bytes_with_temporary(
        &mut self,
        bytes: &[u8],
        temporary_bytes: u64,
    ) -> Result<ObjectId, InterpreterError> {
        let temporary_bytes =
            usize::try_from(temporary_bytes).map_err(|_| InterpreterError::RangeError {
                message: "Buffer transaction temporary memory exceeds host address space"
                    .to_string(),
            })?;
        self.alloc_fresh_buffer_object(bytes.len(), Some(bytes), temporary_bytes)
    }

    pub(super) fn alloc_typed_array_with_fresh_buffer(
        &mut self,
        kind: TypedArrayKind,
        length: usize,
    ) -> Result<ObjectId, InterpreterError> {
        let byte_length = self.checked_typed_array_byte_length(kind, length)?;
        let buffer = self.alloc_array_buffer_object(byte_length)?;
        self.alloc_typed_array_view_object(kind, buffer, 0, byte_length, length)
    }

    pub(super) fn alloc_typed_array_from_values(
        &mut self,
        kind: TypedArrayKind,
        values: &[Value],
    ) -> Result<ObjectId, InterpreterError> {
        let values = self.typed_array_prepare_values(kind, values.to_vec())?;
        let values = values.as_slice();
        let view = self.alloc_typed_array_with_fresh_buffer(kind, values.len())?;
        let buffer = self
            .heap
            .get(view.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .map(|typed_array| typed_array.buffer)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "typed-array view".to_string(),
                got: "ordinary object".to_string(),
            })?;
        self.with_array_buffer_bytes_mut(buffer, |bytes| {
            for (index, value) in values.iter().enumerate() {
                Self::write_typed_array_element_bytes(kind, bytes, index, value)?;
            }
            Ok(())
        })??;
        Ok(view)
    }

    /// ES2020 22.2.4.4 TypedArray(object) step 6: a source with an
    /// @@iterator is read through the iteration protocol (IterableToList):
    /// a generator or iterator, a Map or Set, an object with its own
    /// @@iterator. Arrays with the builtin iterator and typed arrays yield
    /// the same values as their indexed read, and an array-like has no
    /// iterator, so those return `None` for the indexed path. (A Set gave an
    /// empty typed array and a generator was taken for a length.)
    /// Whether the first `@@iterator` on `object`'s chain is a data property
    /// holding undefined or null, which GetMethod (ES2020 7.3.10) answers as
    /// no method: TypedArray(object) then reads it as an array-like
    /// (`new Uint8Array({ [Symbol.iterator]: null, length: 2 })`,
    /// bd-9vouw.378). An accessor or a proxy is not decided here.
    pub(super) fn iterator_method_is_nullish_data(&self, object: ObjectId) -> bool {
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
        let mut current = Some(object);
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else {
                return false;
            };
            let Some(object) = self.heap.get(id.0 as usize) else {
                return false;
            };
            if object.contains_own_runtime_property(&key) {
                return matches!(
                    object.own_runtime_property_value(&key),
                    Some(Value::Undefined | Value::Null)
                );
            }
            current = object.prototype;
        }
        false
    }

    pub(super) fn typed_array_iterable_source(
        &mut self,
        module: Option<&Ir3Module>,
        source: &Value,
    ) -> Result<Option<Vec<Value>>, InterpreterError> {
        let iterate = match source {
            Value::Iterator(_) | Value::Generator(_) => true,
            Value::Object(id) => {
                let (is_array, is_view) = self
                    .heap
                    .get(id.0 as usize)
                    .map_or((false, false), |object| {
                        (object.is_array, object.typed_array.is_some())
                    });
                if is_view {
                    false
                } else if is_array {
                    self.array_from_has_explicit_iterator(*id)?
                } else {
                    let map = self.collection_storage_id(*id, "Map");
                    let set = self.collection_storage_id(*id, "Set");
                    map.is_some()
                        || set.is_some()
                        || (self.array_from_has_explicit_iterator(*id)?
                            && !self.iterator_method_is_nullish_data(*id))
                }
            }
            _ => false,
        };
        if !iterate {
            return Ok(None);
        }
        let iterator = self.init_for_of_iterator(module, source.clone())?;
        let mut values = Vec::new();
        while let Some(value) = self.advance_for_of_iterator(module, iterator.clone())? {
            values.push(value);
        }
        Ok(Some(values))
    }

    pub(super) fn construct_typed_array(
        &mut self,
        module: Option<&Ir3Module>,
        kind: TypedArrayKind,
        args: RegRange,
    ) -> Result<ObjectId, InterpreterError> {
        let first_arg = if args.count == 0 {
            Value::Undefined
        } else {
            self.read_reg(args.start)?
        };

        if matches!(first_arg, Value::Undefined) {
            return self.alloc_typed_array_with_fresh_buffer(kind, 0);
        }

        if let Value::Object(object_id) = first_arg {
            if self
                .heap
                .get(object_id.0 as usize)
                .is_some_and(|object| object.array_buffer.is_some())
            {
                let (byte_offset, byte_length, length, bounds) =
                    self.typed_array_buffer_view_shape(module, kind, object_id, args)?;
                let view = self.alloc_typed_array_view_object(
                    kind,
                    object_id,
                    byte_offset,
                    byte_length,
                    length,
                )?;
                self.register_buffer_view(view, bounds)?;
                return Ok(view);
            }
        }

        // ES2024 23.2.5.1.3-5: the values of an iterable are collected
        // before any is converted; each conversion runs a value's
        // @@toPrimitive/valueOf and may throw (bd-9vouw.273). They were
        // converted without running guest code.
        if let Some(values) = self.typed_array_iterable_source(module, &first_arg)? {
            let values = self.typed_array_element_values(module, kind, values)?;
            return self.alloc_typed_array_from_values(kind, &values);
        }

        if let Value::Object(object_id) = first_arg {
            self.typed_array_content_type_check(kind, &first_arg)?;
            let (is_array, is_view) = self
                .heap
                .get(object_id.0 as usize)
                .map_or((false, false), |object| {
                    (object.is_array, object.typed_array.is_some())
                });
            if is_array || is_view {
                // An Array with the built-in iterator (iterated: its values
                // are read before any conversion) or a typed array.
                let values = self.observable_array_like_values(module, object_id)?;
                let values = self.typed_array_element_values(module, kind, values)?;
                return self.alloc_typed_array_from_values(kind, &values);
            }
            // InitializeTypedArrayFromArrayLike (23.2.5.1.5): its length,
            // the allocation (a RangeError for an impossible length, before
            // any element is read), then Get and Set per index in order.
            let length = self.generic_length(module, object_id)?;
            let length = usize::try_from(length).map_err(|_| InterpreterError::RangeError {
                message: format!("{} length {length} is out of range", kind.type_name()),
            })?;
            let view = self.alloc_typed_array_with_fresh_buffer(kind, length)?;
            // Guest code runs while native locals hold values: no
            // collection until this returns.
            self.gc_nested_request = None;
            for index in 0..length {
                let value =
                    self.generic_get(module, object_id, &Self::generic_index_key(index as u64))?;
                let converted = self.typed_array_element_value(module, kind, value)?;
                self.typed_array_indexed_set_property(view, &index.to_string(), &converted)?;
            }
            return Ok(view);
        }

        let length = self.typed_array_index_from_value(kind, "length", &first_arg)?;
        self.alloc_typed_array_with_fresh_buffer(kind, length)
    }

    pub(super) fn alloc_data_view_object(
        &mut self,
        buffer: ObjectId,
        byte_offset: usize,
        byte_length: usize,
    ) -> Result<ObjectId, InterpreterError> {
        self.ensure_heap_allocation_allowed()?;

        let byte_length_i64 =
            i64::try_from(byte_length).map_err(|_| InterpreterError::RangeError {
                message: format!("DataView byteLength {byte_length} exceeds JS integer storage"),
            })?;
        let byte_offset_i64 =
            i64::try_from(byte_offset).map_err(|_| InterpreterError::RangeError {
                message: format!("DataView byteOffset {byte_offset} exceeds JS integer storage"),
            })?;

        // A DataView inherits from %DataView.prototype% (ES2020 24.3.2.1),
        // as an ArrayBuffer does from its own: `dv instanceof DataView`,
        // `dv.constructor` and members a program adds to the prototype
        // (bd-9vouw.234). Materialized before the view's id is taken, since
        // the first call allocates the prototype object.
        let prototype = self.ensure_builtin_prototype("DataView")?;
        let requested_heap_objects = self.heap_object_count_u32().saturating_add(1);
        if requested_heap_objects > self.config.max_heap_objects {
            return Err(
                self.memory_budget_error(self.estimated_memory_bytes, requested_heap_objects)
            );
        }

        let id =
            ObjectId(
                u32::try_from(self.heap.len()).map_err(|_| InterpreterError::TypeError {
                    expected: "heap capacity".into(),
                    got: format!("exceeded u32::MAX ({})", self.heap.len()),
                })?,
            );

        let mut object = HeapObject::new();
        object.prototype = Some(prototype);
        object.brand = Some(Box::new(JsString::from("DataView")));
        object
            .properties
            .insert("buffer".to_string(), Value::Object(buffer));
        object
            .properties
            .insert("byteLength".to_string(), Value::Int(byte_length_i64));
        object
            .properties
            .insert("byteOffset".to_string(), Value::Int(byte_offset_i64));
        object.data_view = Some(Box::new(DataViewView {
            buffer,
            byte_offset,
            byte_length,
            bounds: None,
        }));

        let object_size = Self::estimate_heap_object_bytes(&object);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(object_size);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, requested_heap_objects));
        }

        self.mutate_heap(|h| h.push(object));
        self.estimated_memory_bytes = requested_bytes;

        if let Some(profiler) = &mut self.profiling_data {
            profiler.record_object_allocation(object_size);
        }

        Ok(id)
    }

    pub(super) fn construct_data_view(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<ObjectId, InterpreterError> {
        let first_arg = if args.count == 0 {
            Value::Undefined
        } else {
            self.read_reg(args.start)?
        };

        let Value::Object(buffer_id) = first_arg else {
            return Err(InterpreterError::TypeError {
                expected: "ArrayBuffer".to_string(),
                got: first_arg.type_name().to_string(),
            });
        };
        if !self
            .heap
            .get(buffer_id.0 as usize)
            .is_some_and(|object| object.array_buffer.is_some())
        {
            let got = self
                .heap
                .get(buffer_id.0 as usize)
                .and_then(HeapObject::brand)
                .unwrap_or("object")
                .to_string();
            return Err(InterpreterError::TypeError {
                expected: "ArrayBuffer".to_string(),
                got,
            });
        }

        let (byte_offset, byte_length, bounds) =
            self.data_view_buffer_view_shape(module, buffer_id, args)?;
        let view = self.alloc_data_view_object(buffer_id, byte_offset, byte_length)?;
        self.register_buffer_view(view, bounds)?;
        Ok(view)
    }

    /// The argument checks of DataView ( buffer, byteOffset, byteLength )
    /// (ES2024 25.3.2.1 steps 2-9) without constructing the view: the
    /// TypeError for a buffer that is not an ArrayBuffer and the
    /// RangeErrors of the offset and length. Callers pass only primitive
    /// offsets and lengths, whose ToIndex has no observable effect.
    pub(super) fn validate_data_view_arguments(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let buffer = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let buffer_id = match buffer {
            Value::Object(id)
                if self
                    .heap
                    .get(id.0 as usize)
                    .is_some_and(|object| object.array_buffer.is_some()) =>
            {
                id
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "ArrayBuffer".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        self.data_view_buffer_view_shape(Some(module), buffer_id, args)?;
        Ok(())
    }

    /// Allocate a new object with an explicit prototype link.
    ///
    /// Returns an error if the heap exceeds `u32::MAX` objects, preventing
    /// silent ObjectId aliasing.
    pub fn alloc_object_with_prototype(
        &mut self,
        prototype: Option<ObjectId>,
    ) -> Result<ObjectId, InterpreterError> {
        self.alloc_object_with_prototype_and_flags(prototype, false)
    }

    /// Allocate a new array object with an explicit prototype link.
    pub fn alloc_array_with_prototype(
        &mut self,
        prototype: Option<ObjectId>,
    ) -> Result<ObjectId, InterpreterError> {
        self.alloc_object_with_prototype_and_flags(prototype, true)
    }

    pub(super) fn alloc_object_with_prototype_and_flags(
        &mut self,
        prototype: Option<ObjectId>,
        is_array: bool,
    ) -> Result<ObjectId, InterpreterError> {
        self.ensure_heap_allocation_allowed()?;

        let requested_heap_objects = self.heap_object_count_u32().saturating_add(1);
        if requested_heap_objects > self.config.max_heap_objects {
            return Err(
                self.memory_budget_error(self.estimated_memory_bytes, requested_heap_objects)
            );
        }
        let id =
            ObjectId(
                u32::try_from(self.heap.len()).map_err(|_| InterpreterError::TypeError {
                    expected: "heap capacity".into(),
                    got: format!("exceeded u32::MAX ({})", self.heap.len()),
                })?,
            );
        let mut object = HeapObject::new();
        object.prototype = prototype;
        object.is_array = is_array;
        // Initialize cached dense length for arrays
        object.cached_dense_length = if is_array { Some(0) } else { None };
        let object_size = Self::estimate_heap_object_bytes(&object);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(object_size);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, requested_heap_objects));
        }
        self.mutate_heap(|h| h.push(object));
        self.estimated_memory_bytes = requested_bytes;

        // Record object allocation profiling
        if let Some(profiler) = &mut self.profiling_data {
            profiler.record_object_allocation(object_size);
        }

        Ok(id)
    }

    pub(super) fn alloc_iterator(
        &mut self,
        iterator: RuntimeIteratorState,
    ) -> Result<u32, InterpreterError> {
        let handle =
            u32::try_from(self.iterators.len()).map_err(|_| InterpreterError::TypeError {
                expected: "iterator table capacity".into(),
                got: format!("exceeded u32::MAX ({})", self.iterators.len()),
            })?;
        let iterator_bytes = Self::estimate_iterator_bytes(&iterator);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(iterator_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.iterators.push(iterator);
        self.estimated_memory_bytes = requested_bytes;
        Ok(handle)
    }

    pub(super) fn expect_iterator_handle(&self, iterator: Value) -> Result<u32, InterpreterError> {
        match iterator {
            Value::Iterator(handle) => Ok(handle),
            other => Err(InterpreterError::TypeError {
                expected: "iterator".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn iterator_state_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut RuntimeIteratorState, InterpreterError> {
        self.iterators
            .get_mut(handle as usize)
            .ok_or(InterpreterError::IteratorNotFound { handle })
    }

    #[cfg(test)]
    pub(super) fn collect_for_in_keys(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
    ) -> Result<Vec<JsString>, InterpreterError> {
        self.collect_for_in_keys_continuing(module, object_id, &[], None)
    }

    /// The for-in keys of `object_id` and its prototype chain. After
    /// `object_id` the walk visits `leading` in order (the backing objects
    /// of a function's parent constructors, bd-9vouw.488), then `continue_at`
    /// when given (a promise's, generator's or iterator's backing object
    /// inherits from its intrinsic prototype, bd-9vouw.149; a function from
    /// its value-level [[Prototype]]), then ordinary prototype links.
    pub(super) fn collect_for_in_keys_continuing(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        leading: &[ObjectId],
        continue_at: Option<ObjectId>,
    ) -> Result<Vec<JsString>, InterpreterError> {
        let mut keys = Vec::new();
        let mut seen = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut leading_levels = leading.iter().copied();
        let mut continue_at = continue_at;

        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                break;
            }
            if self.active_proxy_record(id)?.is_some() {
                // bd-9trje: enumerate a Proxy level's enumerable String keys via
                // the ownKeys + getOwnPropertyDescriptor traps.
                for key in self.proxy_own_enumerable_string_keys(module, id)? {
                    if seen.insert(key.clone()) {
                        keys.push(key);
                    }
                }
            } else {
                for (key, _) in self.indexed_own_entries(id)? {
                    if seen.insert(key.clone()) {
                        keys.push(key);
                    }
                }
                let object = self
                    .heap
                    .get(id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
                for key in object.properties.exact_keys() {
                    // A non-enumerable own key (an array's `length`) is not
                    // visited but still shadows a same-named key further up
                    // the chain.
                    if self.own_runtime_property_visible(id, &key)
                        && seen.insert(key.clone())
                        && object
                            .own_property_attributes(&RuntimePropertyKey::String(key.clone()))
                            .enumerable
                    {
                        keys.push(key);
                    }
                }
            }
            // An exotic value's backing object continues at the value's own
            // [[Prototype]] (a generator's recorded `prototype`, a Promise
            // subclass's, or the intrinsic), not at the backing object's link
            // (bd-9vouw.120).
            current = match leading_levels.next() {
                Some(level) => Some(level),
                None => match continue_at.take() {
                    Some(prototype) => Some(prototype),
                    None => self.proxy_aware_prototype_link(module, id)?,
                },
            };
            depth += 1;
        }

        Ok(keys)
    }

    pub(super) fn collect_for_of_values(
        &self,
        iterable: &Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        match iterable {
            // ES string iteration yields one element per code point, with an
            // unpaired surrogate preserved as its own single-unit element
            // (bd-rdnhc; previously iterated the U+FFFD projection).
            Value::Str(text) => Ok(text
                .code_point_elements()
                .into_iter()
                .map(Value::Str)
                .collect()),
            Value::Object(object_id) => {
                let object = self
                    .heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                let mut indexed_values = object
                    .properties
                    .iter()
                    .filter_map(|(key, value)| key.parse::<u64>().ok().map(|index| (index, value)))
                    .collect::<Vec<_>>();
                indexed_values.sort_by_key(|(index, _)| *index);
                if indexed_values.is_empty() {
                    return Err(InterpreterError::TypeError {
                        expected: "iterable".to_string(),
                        got: iterable.type_name().to_string(),
                    });
                }
                Ok(indexed_values
                    .into_iter()
                    .map(|(_, value)| value.clone())
                    .collect())
            }
            other => Err(InterpreterError::TypeError {
                expected: "iterable".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn mark_deleted_for_in_iterators(&mut self, object_id: ObjectId, key: &JsString) {
        for iterator in self.iterators.iter_mut() {
            if let RuntimeIteratorState::ForIn(state) = iterator
                && state.object_id == object_id
            {
                state.deleted_keys.insert(key.clone());
            }
        }
    }

    /// Record the attributes of the own property `key`. Default attributes
    /// drop the sparse entry; the entry's footprint is charged or released.
    pub(super) fn set_own_property_attributes(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        attributes: PropertyAttributes,
    ) -> Result<(), InterpreterError> {
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let entry_bytes = Self::estimate_property_attributes_entry_bytes(key);
        let previous_bytes = if object.property_attributes.contains_key(key) {
            entry_bytes
        } else {
            0
        };
        let next_bytes = if attributes == PropertyAttributes::DEFAULT {
            0
        } else {
            entry_bytes
        };
        if previous_bytes == 0 && next_bytes == 0 {
            return Ok(());
        }
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        let stored_key = key.clone();
        self.mutate_heap(|heap| {
            let attributes_map = &mut heap[heap_index].property_attributes;
            if attributes == PropertyAttributes::DEFAULT {
                attributes_map.remove(&stored_key);
            } else {
                attributes_map.insert(stored_key, attributes);
            }
        });
        if !attributes.writable
            && let Some(key) = key.as_str()
        {
            self.disconnect_mapped_argument(object_id, key);
        }
        Ok(())
    }

    /// Record the IFC label of one own property under the same total-memory
    /// budget as its value carrier (bd-ojvo1). The sparse map represents
    /// `Public` as absence. Projection makes a rejected label allocation leave
    /// both the heap and the accounting counter unchanged.
    pub(super) fn set_own_runtime_property_label(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        if let Some(binding) = key
            .as_str()
            .and_then(|key| self.mapped_argument_binding(object_id, key))
        {
            return self.set_mapped_argument_value(binding, None, Some(label));
        }
        let heap_index = object_id.0 as usize;
        let Some(current) = self.heap.get(heap_index) else {
            return Err(InterpreterError::ObjectNotFound { id: object_id.0 });
        };
        // A Public label is stored as no entry: with none for the key, there
        // is nothing to remove and the estimate stays (bd-9vouw.504). Every
        // store into a Public-labelled property came through the removal
        // below: two walks of the label map and a heap write of nothing.
        if matches!(label, Label::Public)
            && match key {
                RuntimePropertyKey::String(key) => current.property_labels.get_exact(key).is_none(),
                RuntimePropertyKey::Symbol(symbol) => current
                    .property_labels
                    .baseline_symbol_property(core_symbol_id(*symbol))
                    .is_none(),
            }
        {
            return Ok(());
        }
        let previous_bytes =
            Self::estimate_execution_seed_ordered_label_map_bytes(&current.property_labels);
        if matches!(label, Label::Public) {
            let key = key.clone();
            self.mutate_heap(|heap| match key {
                RuntimePropertyKey::String(key) => {
                    heap[heap_index].property_labels.remove_exact(&key);
                }
                RuntimePropertyKey::Symbol(symbol) => {
                    heap[heap_index]
                        .property_labels
                        .remove_baseline_symbol_property(core_symbol_id(symbol));
                }
            });
            let next_bytes = Self::estimate_execution_seed_ordered_label_map_bytes(
                &self.heap[heap_index].property_labels,
            );
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_bytes)
                .saturating_add(next_bytes);
            return Ok(());
        }
        self.check_temporary_memory_budget(previous_bytes)?;
        let mut projected = current.property_labels.clone();
        match key {
            RuntimePropertyKey::String(key) => {
                projected.insert_exact(key.clone(), label.clone());
            }
            RuntimePropertyKey::Symbol(symbol) => {
                let symbol = core_symbol_id(*symbol);
                projected.insert_baseline_symbol_property(
                    symbol,
                    BaselineSymbolProperty::Data(label.clone()),
                );
            }
        }
        let next_bytes = Self::estimate_execution_seed_ordered_label_map_bytes(&projected);
        self.check_temporary_memory_budget(next_bytes)?;
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.mutate_heap(|heap| heap[heap_index].property_labels = projected);
        Ok(())
    }

    /// Join the stored label of an element read by a native array aggregate
    /// into its pending result label. Resolve the same first owning object
    /// as the value lookup: a hole may inherit a labeled prototype element,
    /// while a Public own element must shadow a Secret inherited element.
    pub(super) fn join_element_stored_label(
        &mut self,
        object_id: ObjectId,
        index: u64,
    ) -> Result<(), InterpreterError> {
        let key = RuntimePropertyKey::String(JsString::from(index.to_string()));
        let label = self.runtime_property_label(object_id, &key);
        if label != Label::Public {
            let joined = self
                .pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public)
                .join(&label);
            self.replace_pending_hostcall_result_label(Some(joined))?;
        }
        Ok(())
    }

    pub(super) fn own_stored_runtime_property_label(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Label {
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return Label::Public;
        };
        match key {
            RuntimePropertyKey::String(key) => object
                .property_labels
                .get_exact(key)
                .cloned()
                .unwrap_or(Label::Public),
            RuntimePropertyKey::Symbol(symbol) => object
                .property_labels
                .baseline_symbol_property(core_symbol_id(*symbol))
                .and_then(|property| match property {
                    BaselineSymbolProperty::Data(label) => Some(label.clone()),
                    BaselineSymbolProperty::Accessor { .. } => None,
                })
                .unwrap_or(Label::Public),
        }
    }

    /// Resolve the stored value label from the first object that owns the
    /// property. This mirrors value lookup, including exact strings, Symbols,
    /// shadowing, bounded prototype traversal, and cycle refusal.
    pub(super) fn runtime_property_label(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Label {
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut visited = ChainGuard::default();
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                break;
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                break;
            };
            if object.contains_own_runtime_property(key) {
                return self.own_stored_runtime_property_label(id, key);
            }
            current = self.observable_prototype_link(object, id);
            depth += 1;
        }
        Label::Public
    }

    #[cfg(test)]
    pub(super) fn set_own_property_label(
        &mut self,
        object_id: ObjectId,
        key: &str,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        self.set_own_runtime_property_label(
            object_id,
            &RuntimePropertyKey::String(JsString::from(key)),
            label,
        )
    }

    #[cfg(test)]
    pub(super) fn own_property_label(&self, object_id: ObjectId, key: &str) -> Label {
        self.runtime_property_label(object_id, &RuntimePropertyKey::String(JsString::from(key)))
    }

    pub(super) fn set_object_runtime_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(&key)?;
        validate_symbol_value(&self.symbol_state, &value).map_err(|got| {
            InterpreterError::TypeError {
                expected: "resolved Symbol value".to_string(),
                got,
            }
        })?;
        let RuntimePropertyKey::String(key) = key else {
            let RuntimePropertyKey::Symbol(symbol) = key else {
                unreachable!("RuntimePropertyKey variants are exhaustive")
            };
            let property = match value {
                Value::Accessor { get, set } => BaselineSymbolProperty::Accessor {
                    get: get.map(|value| value.as_ref().clone()),
                    set: set.map(|value| value.as_ref().clone()),
                },
                value => BaselineSymbolProperty::Data(value),
            };
            return self.set_symbol_property(object_id, symbol, property);
        };
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return Err(InterpreterError::ObjectNotFound { id: object_id.0 });
        };
        let has_exact_only_properties = object.properties.exact_len() != object.properties.len();
        if let Some(key) = key.as_str()
            && !has_exact_only_properties
        {
            return self.set_object_property(object_id, key.to_string(), value);
        }
        self.set_object_projected_property(object_id, key, value)
    }

    pub(super) fn set_symbol_property(
        &mut self,
        object_id: ObjectId,
        symbol: SymbolId,
        property: BaselineSymbolProperty<Value>,
    ) -> Result<(), InterpreterError> {
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if !object.extensible()
            && object
                .properties
                .baseline_symbol_property(core_symbol_id(symbol))
                .is_none()
        {
            return Err(InterpreterError::TypeError {
                expected: "existing property on non-extensible object".to_string(),
                got: "new property".to_string(),
            });
        }
        if object.is_frozen {
            return Err(InterpreterError::TypeError {
                expected: "mutable object".to_string(),
                got: "frozen object".to_string(),
            });
        }
        let validate_property_value = |value: &Value| {
            validate_symbol_value(&self.symbol_state, value).map_err(|got| {
                InterpreterError::TypeError {
                    expected: "resolved Symbol value".to_string(),
                    got,
                }
            })
        };
        match &property {
            BaselineSymbolProperty::Data(value) => validate_property_value(value)?,
            BaselineSymbolProperty::Accessor { get, set } => {
                if let Some(getter) = get {
                    validate_property_value(getter)?;
                }
                if let Some(setter) = set {
                    validate_property_value(setter)?;
                }
            }
        }

        let previous_property_bytes = Self::estimate_ordered_property_map_bytes(&object.properties);
        let temporary_bytes = self
            .estimated_memory_bytes
            .saturating_add(previous_property_bytes);
        if self.memory_request_exceeds_budget(temporary_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(temporary_bytes, self.heap_object_count_u32()));
        }
        let mut projected_properties = object.properties.clone();
        projected_properties.insert_baseline_symbol_property(core_symbol_id(symbol), property);
        let next_property_bytes = Self::estimate_ordered_property_map_bytes(&projected_properties);
        let peak_bytes = self
            .estimated_memory_bytes
            .saturating_add(next_property_bytes);
        if self.memory_request_exceeds_budget(peak_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(peak_bytes, self.heap_object_count_u32()));
        }
        self.apply_memory_component_delta(previous_property_bytes, next_property_bytes)?;
        self.mutate_heap(|heap| heap[heap_index].properties = projected_properties);
        self.gc_write_barrier(object_id);
        Ok(())
    }

    /// Clear a descriptor-as-value property carrier without allocating a
    /// replacement order spine. Internal collection backing objects use this
    /// path so an exact-only guest key cannot be omitted from release
    /// accounting or leave stale exact metadata behind.
    pub(super) fn clear_object_properties(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if object.is_frozen {
            return Err(InterpreterError::TypeError {
                expected: "mutable object".to_string(),
                got: "frozen object".to_string(),
            });
        }
        let released_bytes = Self::estimate_ordered_property_map_bytes(&object.properties)
            .saturating_add(Self::estimate_execution_seed_ordered_label_map_bytes(
                &object.property_labels,
            ));
        self.mutate_heap(|heap| {
            heap[heap_index].properties = OrderedStringMap::new();
            heap[heap_index].property_labels = OrderedStringMap::new();
        });
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
        self.gc_write_barrier(object_id);
        Ok(())
    }

    pub(super) fn set_object_projected_property(
        &mut self,
        object_id: ObjectId,
        key: JsString,
        value: Value,
    ) -> Result<(), InterpreterError> {
        validate_symbol_value(&self.symbol_state, &value).map_err(|got| {
            InterpreterError::TypeError {
                expected: "resolved Symbol value".to_string(),
                got,
            }
        })?;
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if !object.extensible() && !object.properties.contains_exact_key(&key) {
            return Err(InterpreterError::TypeError {
                expected: "existing property on non-extensible object".to_string(),
                got: "new property".to_string(),
            });
        }
        if object.is_frozen {
            return Err(InterpreterError::TypeError {
                expected: "mutable object".to_string(),
                got: "frozen object".to_string(),
            });
        }

        let mapped_accessor_key = if let Some(binding) = key
            .as_str()
            .and_then(|key| self.mapped_argument_binding(object_id, key))
        {
            if !matches!(value, Value::Accessor { .. }) {
                return self.set_mapped_argument_value(binding, Some(value), None);
            }
            Some(key.as_str().expect("mapped index").to_string())
        } else {
            None
        };

        let array_length_assignment = if object.is_array && key.as_str() == Some("length") {
            Some(Self::normalize_array_length_assignment(&value)?)
        } else {
            None
        };
        let deleted_index_keys = array_length_assignment
            .and_then(|new_length| Self::array_length_truncation_keys(object, new_length))
            .unwrap_or_default();
        let projected_value = array_length_assignment.map_or(value, Value::Int);
        let mut projected_cached_dense_length = object.cached_dense_length;
        if object.is_array
            && key.as_str() != Some("length")
            && projected_cached_dense_length.is_some()
        {
            if let Some(index) = key.as_str().and_then(Self::canonical_array_index_key) {
                if index > projected_cached_dense_length.unwrap_or(0) {
                    projected_cached_dense_length = None;
                }
            } else {
                projected_cached_dense_length = None;
            }
        }
        if let Some(new_length) = array_length_assignment {
            projected_cached_dense_length = u32::try_from(new_length).ok();
        }

        // Exact-only keys are rare. Projecting the private carrier first lets
        // the budget gate include activation of every hidden order sidecar and
        // reject without any heap or seed-surface mutation.
        let previous_property_bytes = Self::estimate_ordered_property_map_bytes(&object.properties);
        let temporary_bytes = self
            .estimated_memory_bytes
            .saturating_add(previous_property_bytes);
        if self.memory_request_exceeds_budget(temporary_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(temporary_bytes, self.heap_object_count_u32()));
        }
        let mut projected_properties = object.properties.clone();
        for deleted_key in &deleted_index_keys {
            projected_properties.remove(deleted_key);
        }
        projected_properties.insert_exact(key, projected_value);
        let next_property_bytes = Self::estimate_ordered_property_map_bytes(&projected_properties);
        let projected_temporary_bytes = self
            .estimated_memory_bytes
            .saturating_add(next_property_bytes);
        if self.memory_request_exceeds_budget(
            projected_temporary_bytes,
            self.config.max_total_memory_bytes,
        ) {
            return Err(
                self.memory_budget_error(projected_temporary_bytes, self.heap_object_count_u32())
            );
        }
        self.apply_memory_component_delta(previous_property_bytes, next_property_bytes)?;

        self.mutate_heap(|heap| {
            let object = &mut heap[heap_index];
            object.properties = projected_properties;
            object.cached_dense_length = projected_cached_dense_length;
        });
        if let Some(key) = mapped_accessor_key {
            self.disconnect_mapped_argument(object_id, &key);
        }
        for deleted_key in &deleted_index_keys {
            self.mark_deleted_for_in_iterators(object_id, &JsString::from(deleted_key.as_str()));
            let deleted_key = RuntimePropertyKey::String(JsString::from(deleted_key.as_str()));
            self.set_own_runtime_property_label(object_id, &deleted_key, &Label::Public)?;
            self.set_own_property_attributes(object_id, &deleted_key, PropertyAttributes::DEFAULT)?;
        }
        self.gc_write_barrier(object_id);
        Ok(())
    }

    pub fn set_object_property(
        &mut self,
        object_id: ObjectId,
        key: String,
        value: Value,
    ) -> Result<(), InterpreterError> {
        validate_symbol_value(&self.symbol_state, &value).map_err(|got| {
            InterpreterError::TypeError {
                expected: "resolved Symbol value".to_string(),
                got,
            }
        })?;
        let heap_index = object_id.0 as usize;
        let Some(object) = self.heap.get(heap_index) else {
            return Err(InterpreterError::ObjectNotFound { id: object_id.0 });
        };
        if object.properties.exact_len() != object.properties.len() {
            return self.set_object_projected_property(object_id, JsString::from(key), value);
        }
        if !object.extensible() && !object.properties.contains_key(&key) {
            return Err(InterpreterError::TypeError {
                expected: "existing property on non-extensible object".to_string(),
                got: "new property".to_string(),
            });
        }
        if object.is_frozen {
            return Err(InterpreterError::TypeError {
                expected: "mutable object".to_string(),
                got: "frozen object".to_string(),
            });
        }
        let mapped_accessor_key =
            if let Some(binding) = self.mapped_argument_binding(object_id, &key) {
                if !matches!(value, Value::Accessor { .. }) {
                    return self.set_mapped_argument_value(binding, Some(value), None);
                }
                Some(key.clone())
            } else {
                None
            };
        let array_length_assignment = if object.is_array && key == "length" {
            Some(Self::normalize_array_length_assignment(&value)?)
        } else {
            None
        };
        let deleted_index_keys = array_length_assignment
            .and_then(|new_length| Self::array_length_truncation_keys(object, new_length))
            .unwrap_or_default();

        let previous_bytes = object.properties.get(&key).map_or(0, |previous| {
            Self::estimate_property_entry_bytes(&key, previous)
        });
        let deleted_index_bytes = deleted_index_keys
            .iter()
            .filter_map(|deleted_key| {
                object
                    .properties
                    .get(deleted_key)
                    .map(|value| Self::estimate_property_entry_bytes(deleted_key, value))
            })
            .sum::<u64>();
        let value = array_length_assignment.map_or(value, Value::Int);
        let new_bytes = Self::estimate_property_entry_bytes(&key, &value);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(new_bytes)
            .saturating_sub(deleted_index_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }

        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(heap_index) {
                // Check if setting this property would make array sparse.
                if object.is_array && key != "length" && object.cached_dense_length.is_some() {
                    if let Some(index) = Self::canonical_array_index_key(&key) {
                        let current_len = object.cached_dense_length.unwrap_or(0);
                        // If setting an index that skips elements, array becomes sparse
                        if index > current_len {
                            object.cached_dense_length = None;
                        }
                    } else {
                        // Non-numeric property on array, could be sparse
                        object.cached_dense_length = None;
                    }
                }
                if let Some(new_length) = array_length_assignment {
                    for deleted_key in &deleted_index_keys {
                        object.properties.remove(deleted_key);
                    }
                    object.cached_dense_length = u32::try_from(new_length).ok();
                }

                object.properties.insert(key, value);
            }
        });
        self.estimated_memory_bytes = requested_bytes;
        if let Some(key) = mapped_accessor_key {
            self.disconnect_mapped_argument(object_id, &key);
        }
        for deleted_key in &deleted_index_keys {
            self.mark_deleted_for_in_iterators(object_id, &JsString::from(deleted_key.as_str()));
            let deleted_key = RuntimePropertyKey::String(JsString::from(deleted_key.as_str()));
            self.set_own_runtime_property_label(object_id, &deleted_key, &Label::Public)?;
            self.set_own_property_attributes(object_id, &deleted_key, PropertyAttributes::DEFAULT)?;
        }

        // Trigger write barrier for GC correctness when setting object properties
        self.gc_write_barrier(object_id);

        Ok(())
    }

    /// DeletePropertyOrThrow (ES2020 7.3.9) of an element an Array method
    /// removes (pop, shift, splice): a non-configurable element, such as
    /// one of a sealed array's, is a TypeError. `Object.seal([1, 2, 3]).pop()`
    /// returned 3 and shrank the sealed array (bd-9vouw.250). A frozen array
    /// is still refused by `remove_object_property` and its `length` write.
    pub(super) fn array_delete_or_throw(
        &mut self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<bool, InterpreterError> {
        let property = RuntimePropertyKey::String(JsString::from(key));
        let non_configurable = self.heap.get(object_id.0 as usize).is_some_and(|object| {
            object.own_runtime_property_value(&property).is_some()
                && !object.own_property_attributes(&property).configurable
        });
        if non_configurable {
            return Err(InterpreterError::TypeError {
                expected: "a configurable array element".to_string(),
                got: format!("Cannot delete property '{key}' of [object Array]"),
            });
        }
        self.remove_object_property(object_id, key)
    }

    pub(super) fn remove_object_property(
        &mut self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<bool, InterpreterError> {
        let heap_index = object_id.0 as usize;
        let has_exact_only_properties = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .properties
            .exact_len()
            != self.heap[heap_index].properties.len();
        if has_exact_only_properties {
            return self.remove_object_carrier_property(object_id, &JsString::from(key));
        }

        // Check if object exists and is not frozen
        if let Some(object) = self.heap.get(heap_index) {
            if object.is_frozen {
                return Ok(false);
            }
        } else {
            return Err(InterpreterError::ObjectNotFound { id: object_id.0 });
        }

        let removed_bytes = self.heap[heap_index]
            .properties
            .get(key)
            .map_or(0, |value| Self::estimate_property_entry_bytes(key, value));
        let mut removed = None;
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(heap_index) {
                // Removing properties from arrays makes them sparse
                if object.is_array && key != "length" && object.cached_dense_length.is_some() {
                    if key.parse::<u32>().is_ok() {
                        // Removing a numeric index makes array sparse
                        object.cached_dense_length = None;
                    }
                }

                removed = object.properties.remove(key);
            }
        });
        if removed.is_some() {
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(removed_bytes);
            self.disconnect_mapped_argument(object_id, key);
            let removed_key = RuntimePropertyKey::String(JsString::from(key));
            self.set_own_runtime_property_label(object_id, &removed_key, &Label::Public)?;
            self.set_own_property_attributes(object_id, &removed_key, PropertyAttributes::DEFAULT)?;
        }
        Ok(removed.is_some())
    }

    pub(super) fn remove_object_runtime_property(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        self.validate_executable_property_key(key)?;
        if let RuntimePropertyKey::Symbol(symbol) = key {
            return self.remove_symbol_property(object_id, *symbol);
        }
        let has_exact_only_properties = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .properties
            .exact_len()
            != self.heap[object_id.0 as usize].properties.len();
        if let Some(key) = key.as_str()
            && !has_exact_only_properties
        {
            return self.remove_object_property(object_id, key);
        }
        let RuntimePropertyKey::String(key) = key else {
            unreachable!("Symbol keys returned above")
        };
        self.remove_object_carrier_property(object_id, key)
    }

    pub(super) fn remove_symbol_property(
        &mut self,
        object_id: ObjectId,
        symbol: SymbolId,
    ) -> Result<bool, InterpreterError> {
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if object.is_frozen {
            return Ok(false);
        }
        if object
            .properties
            .baseline_symbol_property(core_symbol_id(symbol))
            .is_none()
        {
            return Ok(false);
        }
        let previous_property_bytes = Self::estimate_ordered_property_map_bytes(&object.properties);
        self.mutate_heap(|heap| {
            let properties = &mut heap[heap_index].properties;
            properties.remove_baseline_symbol_property(core_symbol_id(symbol));
            if properties.exact_len() == properties.len() {
                let normalized = properties.normalize_data_only_exact_sidecars();
                debug_assert!(normalized);
            }
        });
        let next_property_bytes =
            Self::estimate_ordered_property_map_bytes(&self.heap[heap_index].properties);
        self.apply_memory_component_delta(previous_property_bytes, next_property_bytes)?;
        let removed_key = RuntimePropertyKey::Symbol(symbol);
        self.set_own_runtime_property_label(object_id, &removed_key, &Label::Public)?;
        self.set_own_property_attributes(object_id, &removed_key, PropertyAttributes::DEFAULT)?;
        Ok(true)
    }

    pub(super) fn remove_object_carrier_property(
        &mut self,
        object_id: ObjectId,
        key: &JsString,
    ) -> Result<bool, InterpreterError> {
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if object.is_frozen {
            return Ok(false);
        }
        if !object.properties.contains_exact_key(key) {
            return Ok(false);
        }
        let previous_property_bytes = Self::estimate_ordered_property_map_bytes(&object.properties);
        let key_is_array_index = key.as_str().is_some_and(|key| key.parse::<u32>().is_ok());
        self.mutate_heap(|heap| {
            let object = &mut heap[heap_index];
            object.properties.remove_exact(key);
            if object.properties.exact_len() == object.properties.len() {
                // Engine accessors are ordinary map values, so once the final
                // exact-only key is gone we can normalize away ordinary-string
                // carrier metadata. Symbol chronology is stored independently.
                let normalized = object.properties.normalize_data_only_exact_sidecars();
                debug_assert!(normalized);
            }
            if object.is_array && object.cached_dense_length.is_some() && key_is_array_index {
                object.cached_dense_length = None;
            }
        });
        let next_property_bytes =
            Self::estimate_ordered_property_map_bytes(&self.heap[heap_index].properties);
        self.apply_memory_component_delta(previous_property_bytes, next_property_bytes)?;
        if let Some(key) = key.as_str() {
            self.disconnect_mapped_argument(object_id, key);
        }
        let removed_key = RuntimePropertyKey::String(key.clone());
        self.set_own_runtime_property_label(object_id, &removed_key, &Label::Public)?;
        self.set_own_property_attributes(object_id, &removed_key, PropertyAttributes::DEFAULT)?;
        Ok(true)
    }

    pub(super) fn function_prototype_owner_id(module: &Ir3Module) -> ContentHash {
        let mut digest = Sha256::new();
        digest.update(b"FrankenEngine.FunctionPrototypeOwner.v1");
        digest.update(module.header.schema_version.major.to_le_bytes());
        digest.update(module.header.schema_version.minor.to_le_bytes());
        digest.update(module.header.schema_version.patch.to_le_bytes());
        digest.update(module.header.level.as_str().as_bytes());
        match module.header.source_hash {
            Some(source_hash) => {
                digest.update([1]);
                digest.update(source_hash.as_bytes());
            }
            None => digest.update([0]),
        }
        digest.update(
            u64::try_from(module.header.source_label.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        digest.update(module.header.source_label.as_bytes());
        ContentHash::from_bytes(digest.finalize().into())
    }

    /// [`Self::function_prototype_owner_id`], [`Self::closure_prototype_owner_id`]
    /// and the own-property owners of `module`'s functions, digested once per
    /// module header (the digests read nothing else).
    pub(super) fn prototype_owner_ids(&self, module: &Ir3Module) -> PrototypeOwnerIds {
        if let Some((_, ids)) = self
            .prototype_owner_ids
            .borrow()
            .iter()
            .find(|(header, _)| *header == module.header)
        {
            return *ids;
        }
        let function = Self::function_prototype_owner_id(module);
        let closure = Self::closure_prototype_owner_id(module);
        let own_property = [0u8, 1, 2, 3, 4].map(|kind| {
            Self::function_own_property_owner(kind, if kind == 0 { &function } else { &closure })
        });
        let ids = PrototypeOwnerIds {
            function,
            closure,
            own_property,
        };
        let mut memo = self.prototype_owner_ids.borrow_mut();
        if memo.len() >= PROTOTYPE_OWNER_MEMO_ENTRIES {
            memo.remove(0);
        }
        memo.push((module.header.clone(), ids));
        ids
    }

    pub(super) fn ensure_function_prototype(
        &mut self,
        module: &Ir3Module,
        func_idx: u32,
    ) -> Result<ObjectId, InterpreterError> {
        let key = (self.prototype_owner_ids(module).function, func_idx);
        if let Some(existing) = self.function_prototypes.get(&key) {
            Ok(*existing)
        } else {
            let prototype = self.alloc_object_with_prototype(None)?;
            self.mutate_function_prototypes(|fp| fp.insert(key, prototype));
            self.install_prototype_constructor(prototype, Value::Function(func_idx))?;
            Ok(prototype)
        }
    }

    /// MakeConstructor (ES2020 9.2.5 step 5) and ClassDefinitionEvaluation
    /// (14.6.13 step 16): a function's own `prototype` object carries a
    /// writable, non-enumerable, configurable `constructor` back to the
    /// function, so `new F().constructor === F`.
    pub(super) fn install_prototype_constructor(
        &mut self,
        prototype: ObjectId,
        constructor: Value,
    ) -> Result<(), InterpreterError> {
        self.set_object_property(prototype, "constructor".to_string(), constructor)?;
        self.set_own_property_attributes(
            prototype,
            &RuntimePropertyKey::String(JsString::from("constructor")),
            PropertyAttributes {
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
    }

    pub(super) fn closure_prototype_owner_id(module: &Ir3Module) -> ContentHash {
        let module_owner = Self::function_prototype_owner_id(module);
        let mut digest = Sha256::new();
        digest.update(b"FrankenEngine.ClosurePrototypeOwner.v1");
        digest.update(module_owner.as_bytes());
        ContentHash::from_bytes(digest.finalize().into())
    }

    pub(super) fn ensure_closure_prototype(
        &mut self,
        module: &Ir3Module,
        closure_id: u32,
    ) -> Result<ObjectId, InterpreterError> {
        if self.closure_method_metadata.contains_key(&closure_id) {
            return Err(InterpreterError::TypeError {
                expected: "constructible closure".to_string(),
                got: format!("concise method closure#{closure_id}"),
            });
        }
        self.closures
            .get(closure_id as usize)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid closure".to_string(),
                got: format!("closure#{closure_id} not found"),
            })?;
        let key = (self.prototype_owner_ids(module).closure, closure_id);
        if let Some(existing) = self.function_prototypes.get(&key) {
            Ok(*existing)
        } else {
            let prototype = self.alloc_object_with_prototype(None)?;
            self.mutate_function_prototypes(|prototypes| prototypes.insert(key, prototype));
            self.install_prototype_constructor(prototype, Value::Closure(closure_id))?;
            Ok(prototype)
        }
    }

    /// One default prototype per generated construction occurrence. This
    /// registry participates in realm snapshots, memory accounting and GC roots.
    pub(super) fn ensure_generated_function_prototype(
        &mut self,
        builtin: &BuiltinFunction,
    ) -> Result<ObjectId, InterpreterError> {
        let (owner_program_id, artifact_id) = Self::parse_generated_function_handle(builtin)?;
        self.resolve_generated_function_artifact(owner_program_id, artifact_id)?;
        let mut digest = Sha256::new();
        digest.update(b"FrankenEngine.GeneratedFunctionPrototype.v1");
        digest.update(artifact_id.as_bytes());
        let key = (ContentHash::from_bytes(digest.finalize().into()), 0);
        if let Some(prototype) = self.function_prototypes.get(&key) {
            return Ok(*prototype);
        }
        let prototype = self.alloc_object_with_prototype(None)?;
        self.mutate_function_prototypes(|prototypes| prototypes.insert(key, prototype));
        self.install_prototype_constructor(prototype, Value::BuiltinFunction(builtin.clone()))?;
        Ok(prototype)
    }

    /// Native effect factories also retain the selected constructor and
    /// new.target provenance while allocating their host-backed state.
    /// This includes Reflect.construct and a derived class's super() path.
    pub(super) fn construct_builtin_with_new_target_and_labels(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        new_target: &Value,
        callee_label: &Label,
        new_target_label: &Label,
    ) -> Result<Value, InterpreterError> {
        if !builtin.kind.observes_host_effect_selection() {
            return self.construct_builtin_with_new_target(module, builtin, args, new_target);
        }
        self.clear_pending_hostcall_result_label();
        let observation = self.begin_property_observation([])?;
        let outcome = (|| {
            let selection =
                self.clone_dominant_label_with_temporary_budget(callee_label, new_target_label, 0)?;
            self.json_observe_label(selection)?;
            self.construct_builtin_with_new_target(module, builtin, args, new_target)
        })();
        self.finish_property_read_observation(observation, outcome)
    }

    /// [[Construct]] of a builtin constructor with an explicit new.target
    /// (`Reflect.construct(B, args, F)`, or `B` as a class's parent): the
    /// builtin's own construction, then new.target's prototype. `Number`,
    /// `String` and `Boolean` construct their wrapper objects, as `new` does
    /// (bd-9vouw.48); `Symbol` and `BigInt` are not constructors.
    pub(super) fn construct_builtin_with_new_target(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        new_target: &Value,
    ) -> Result<Value, InterpreterError> {
        let standard_name = (builtin.kind == BuiltinFunctionKind::StandardConstructor)
            .then(|| Self::standard_constructor_name(builtin).ok())
            .flatten();
        if let Some(name @ ("Symbol" | "BigInt")) = standard_name {
            return Err(InterpreterError::TypeError {
                expected: "constructor".to_string(),
                got: format!("{name} is not a constructor"),
            });
        }
        // ES2020 21.1.1.1 step 2: constructed, String is ToString(value), a
        // TypeError for a Symbol (only a call answers its descriptive string).
        if standard_name == Some("String")
            && matches!(self.builtin_arg(args, 0)?, Some(Value::Symbol(_)))
        {
            return Err(Self::symbol_to_string_error());
        }
        // Promise ( executor ) (ES2024 27.2.3.1 step 2) and DataView
        // (25.3.2.1 steps 2-9) validate their arguments before
        // GetPrototypeFromConstructor; the read below came first for every
        // builtin, so a throwing `prototype` getter on newTarget hid their
        // TypeError / RangeError. ToIndex of an object offset or length is
        // observable, so a DataView is validated up front only when both are
        // primitives; construction validates again after the read, as the
        // specification re-checks the buffer then.
        if builtin.kind == BuiltinFunctionKind::PromiseConstructor {
            let executor = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
            if !executor.is_callable() {
                return Err(InterpreterError::TypeError {
                    expected: "a callable Promise executor".to_string(),
                    got: format!(
                        "Promise resolver {} is not a function",
                        executor.type_name()
                    ),
                });
            }
        }
        if standard_name == Some("DataView") {
            let mut primitive = true;
            for index in 1..3 {
                primitive &= !self
                    .builtin_arg(args, index)?
                    .is_some_and(|value| value.is_object_like());
            }
            if primitive {
                self.validate_data_view_arguments(module, args)?;
            }
        }
        // GetPrototypeFromConstructor(newTarget, default) (ES2024 10.1.14):
        // Get(newTarget, "prototype") observably (a getter or proxy trap runs
        // and may throw), before the construction reads its arguments; a
        // Standard constructors fall back to their own intrinsic prototype
        // (bd-9vouw.273); ordinary process functions use %Object.prototype%.
        self.gc_nested_request = None;
        let prototype = match self.get_v(
            module,
            new_target,
            &RuntimePropertyKey::String(JsString::from("prototype")),
        )? {
            Value::Object(prototype) => prototype,
            _ if builtin.kind == BuiltinFunctionKind::NativeChildProcessFunction => {
                self.ensure_builtin_prototype("Object")?
            }
            _ => self.default_constructor_prototype_for_value(
                module,
                &Value::BuiltinFunction(builtin.clone()),
            )?,
        };
        // ES2025 27.1.3.1: abstract unless NewTarget is a subclass, whose
        // instance is an ordinary object from NewTarget's prototype.
        if standard_name == Some("Iterator") {
            if matches!(new_target, Value::BuiltinFunction(target)
                if target.kind == BuiltinFunctionKind::StandardConstructor
                    && Self::standard_constructor_name(target).ok() == Some("Iterator"))
            {
                return Err(self.abstract_iterator_construction_error());
            }
            return Ok(Value::Object(
                self.alloc_object_with_prototype(Some(prototype))?,
            ));
        }
        let mut result = match standard_name {
            _ if builtin.kind == BuiltinFunctionKind::DateConstructor => {
                self.dispatch_builtin_hostcall("builtin:Date", args, Some(module))?
            }
            Some("RegExp") => {
                self.dispatch_builtin_hostcall("builtin:RegExp", args, Some(module))?
            }
            Some(name) if Self::buffer_family_constructor(name) => {
                self.dispatch_builtin_hostcall(&format!("builtin:{name}"), args, Some(module))?
            }
            Some(name) if event_target::EVENT_TARGET_FAMILY.contains(&name) => {
                self.construct_event_target_family(module, name, args)?
            }
            Some("Blob") => self.construct_blob(module, args)?,
            Some("SharedArrayBuffer") => {
                self.dispatch_builtin_hostcall("builtin:SharedArrayBuffer", args, Some(module))?
            }
            // Constructed rather than called (call_standard_constructor
            // throws for them): Reflect.construct(Map, ...), a value
            // `new M()` with M = Map, a derived class's super().
            // WeakRef and FinalizationRegistry too (ES2021 26.1.1.1,
            // 26.2.1.1): a subclass's super() threw "requires 'new'"
            // (bd-9vouw.357).
            Some(
                name @ ("Map" | "Set" | "WeakMap" | "WeakSet" | "WeakRef" | "FinalizationRegistry"),
            ) => self.dispatch_builtin_hostcall(&format!("builtin:{name}"), args, Some(module))?,
            _ => self.dispatch_builtin_function(module, builtin, args, None, None)?,
        };
        if matches!(standard_name, Some("Number" | "String" | "Boolean"))
            && !result.is_object_like()
        {
            result = Value::Object(self.alloc_primitive_wrapper(result)?);
        }
        // Node's process functions are ordinary constructors: an explicitly
        // returned object wins, while an encoded stdout string leaves the
        // newly constructed receiver as the result.
        if builtin.kind == BuiltinFunctionKind::NativeChildProcessFunction {
            return if result.is_object_like() {
                Ok(result)
            } else {
                self.alloc_object_with_prototype(Some(prototype))
                    .map(Value::Object)
            };
        }
        // Node's HTTP factories are ordinary functions that explicitly
        // return a request or server. [[Construct]] must keep that result's
        // prototype rather than install createServer/get/request.prototype.
        if builtin.kind == BuiltinFunctionKind::NativeHttpFunction
            && !matches!(
                &*builtin.module_specifier,
                "builtin:HttpAgent" | "builtin:HttpsAgent"
            )
        {
            return Ok(result);
        }
        // bd-9vouw.137: a promise has no ordinary object of its own; a
        // subclass's prototype goes on its backing object, which its
        // [[Get]], instanceof and getPrototypeOf consult.
        if let Value::Promise(_) = result {
            if self.builtin_prototypes.get("Promise") != Some(&prototype) {
                let backing = self
                    .ensure_function_own_property_object(module, &result)?
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "promise with property storage".to_string(),
                        got: "promise without property storage".to_string(),
                    })?;
                self.mutate_heap(|heap| {
                    if let Some(object) = heap.get_mut(backing.0 as usize) {
                        object.prototype = Some(prototype);
                    }
                });
            }
            return Ok(result);
        }
        // bd-9vouw.326: a Function, GeneratorFunction, AsyncFunction or
        // AsyncGeneratorFunction subclass's instance is the function built
        // from source text, whose [[Prototype]] is the subclass prototype:
        // kept on its backing object, as a derived class constructor's parent
        // is (`function_value_prototype` reads it there).
        if result.is_callable() {
            let intrinsic = self.function_value_prototype(Some(module), &result)?;
            if intrinsic != Value::Object(prototype) {
                let backing = self
                    .ensure_function_own_property_object(module, &result)?
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "function with property storage".to_string(),
                        got: "function without property storage".to_string(),
                    })?;
                self.mutate_heap(|heap| {
                    if let Some(object) = heap.get_mut(backing.0 as usize) {
                        object.prototype = Some(prototype);
                    }
                });
            }
            return Ok(result);
        }
        let Value::Object(object_id) = result else {
            return Err(InterpreterError::TypeError {
                expected: "object result from constructible builtin target".to_string(),
                got: result.type_name().to_string(),
            });
        };
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(object_id.0 as usize) {
                object.prototype = Some(prototype);
            }
        });
        Ok(Value::Object(object_id))
    }

    /// bd-9vouw.137: the [[Prototype]] a promise built through a Promise
    /// subclass records on its backing object; `None` for any other value
    /// and for a promise that reports %Promise.prototype%.
    pub(super) fn promise_prototype_override(
        &self,
        module: &Ir3Module,
        value: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        if !matches!(value, Value::Promise(_)) {
            return Ok(None);
        }
        Ok(self
            .function_own_property_object(module, value)?
            .and_then(|backing| self.heap.get(backing.0 as usize))
            .and_then(|object| object.prototype))
    }

    /// The object a promise, generator or async generator inherits from in
    /// place of its intrinsic prototype: a Promise subclass instance's
    /// (bd-9vouw.137), the `prototype` a generator's function held at the
    /// call (bd-9vouw.120).
    pub(super) fn exotic_prototype_override(
        &self,
        module: &Ir3Module,
        value: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let generator_id = match value {
            Value::Promise(_) => return self.promise_prototype_override(module, value),
            Value::Generator(id) => *id,
            Value::AsyncGeneratorObject(id) => match self.async_generators.get(*id as usize) {
                Some(generator) => generator.generator_id,
                None => return Ok(None),
            },
            _ => return Ok(None),
        };
        Ok(self
            .generators
            .get(generator_id as usize)
            .and_then(|generator| generator.prototype))
    }

    /// The `prototype` property of a generator or async generator function
    /// (bd-9vouw.120): an assigned value, else the function's own object,
    /// created on first use, which inherits %GeneratorPrototype% /
    /// %AsyncGeneratorPrototype% and has no `constructor` (ES2020 14.4.11).
    /// `None` for other values.
    pub(super) fn generator_function_prototype(
        &mut self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let (closure_id, intrinsic) = match function {
            Value::GeneratorFunction(id) => (*id, GENERATOR_PROTOTYPE),
            Value::AsyncGeneratorFunction(id) => (*id, ASYNC_GENERATOR_PROTOTYPE),
            _ => return Ok(None),
        };
        if let Some((value, _)) = self.constructor_prototype_override(module, function)? {
            return Ok(Some(value));
        }
        let owner_module = self.foreign_closure_module(function, module)?;
        let key = (
            self.prototype_owner_ids(owner_module.as_deref().unwrap_or(module))
                .closure,
            closure_id,
        );
        if let Some(existing) = self.function_prototypes.get(&key) {
            return Ok(Some(Value::Object(*existing)));
        }
        let parent = self.ensure_builtin_prototype(intrinsic)?;
        let prototype = self.alloc_object_with_prototype(Some(parent))?;
        self.mutate_function_prototypes(|prototypes| prototypes.insert(key, prototype));
        Ok(Some(Value::Object(prototype)))
    }

    /// The prototype a generator made by calling `function` inherits from
    /// (OrdinaryCreateFromConstructor in EvaluateBody, ES2020 14.4.10): its
    /// `prototype` when that is an object, else the intrinsic (`None`).
    pub(super) fn generator_instance_prototype(
        &mut self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        Ok(match self.generator_function_prototype(module, function)? {
            Some(Value::Object(prototype)) => Some(prototype),
            _ => None,
        })
    }

    pub(super) fn constructor_function_index(
        &self,
        value: &Value,
    ) -> Result<u32, InterpreterError> {
        match value {
            Value::Function(index) => Ok(*index),
            Value::Closure(closure_id)
                if !self.closure_method_metadata.contains_key(closure_id)
                    && !self.arrow_lexical_this.contains_key(closure_id) =>
            {
                self.closure_function_index(*closure_id)
            }
            _ => Err(InterpreterError::TypeError {
                expected: "constructor function".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    pub(super) fn is_constructible_value(&self, value: &Value) -> bool {
        match value {
            Value::Function(_) => true,
            Value::Closure(closure_id) => {
                self.closures.get(*closure_id as usize).is_some()
                    && !self.closure_method_metadata.contains_key(closure_id)
                    && !self.arrow_lexical_this.contains_key(closure_id)
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::BoundFunction =>
            {
                self.bound_function_parts(builtin)
                    .is_ok_and(|(target, ..)| self.is_constructible_value(&target))
            }
            // A proxy is a constructor exactly when its target is (ES2020
            // 9.5.14 step 7), revoked or not.
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::CallableProxy =>
            {
                Self::callable_proxy_record_id(builtin)
                    .ok()
                    .and_then(|proxy| self.proxy_call_target(proxy))
                    .is_some_and(|target| self.is_constructible_value(&target))
            }
            Value::BuiltinFunction(builtin) => builtin.kind.is_constructible(),
            _ => false,
        }
    }

    pub(super) fn function_uses_lexical_super(
        &self,
        module: &Ir3Module,
        function_index: u32,
    ) -> Result<bool, InterpreterError> {
        Ok(self
            .lexical_super_functions(module)?
            .get(function_index as usize)
            .copied()
            .unwrap_or(false))
    }

    /// bd-9vouw.159: for every function of `module`, whether it reads the
    /// lexical `super` itself or in a closure it creates (transitively),
    /// computed once per module header. Each closure creation used to answer
    /// for its one function by sorting the whole function table and walking
    /// from it: O(F log F) per closure (8.4% of scale_8000's time).
    pub(super) fn lexical_super_functions(
        &self,
        module: &Ir3Module,
    ) -> Result<std::sync::Arc<Vec<bool>>, InterpreterError> {
        if let Some((_, uses)) = self
            .lexical_super_functions
            .borrow()
            .iter()
            .find(|(header, _)| *header == module.header)
        {
            return Ok(std::sync::Arc::clone(uses));
        }
        let function_count = module.function_table.len();
        let temporary_bytes = u64::try_from(function_count)
            .unwrap_or(u64::MAX)
            .saturating_mul(
                (std::mem::size_of::<bool>()
                    + std::mem::size_of::<Vec<usize>>()
                    + std::mem::size_of::<(usize, usize)>() * 2) as u64,
            )
            .saturating_add(
                (std::mem::size_of::<Vec<bool>>()
                    + std::mem::size_of::<Vec<Vec<usize>>>()
                    + std::mem::size_of::<Vec<(usize, usize)>>() * 2) as u64,
            );
        self.check_temporary_memory_budget(temporary_bytes)?;

        let mut ordered_entries: Vec<(usize, usize)> = module
            .function_table
            .iter()
            .enumerate()
            .map(|(index, function)| (function.entry as usize, index))
            .collect();
        ordered_entries.sort_unstable();
        let mut function_ranges = vec![(0usize, 0usize); function_count];
        let mut offset = 0;
        while offset < ordered_entries.len() {
            let start = ordered_entries[offset].0;
            let mut next = offset + 1;
            while next < ordered_entries.len() && ordered_entries[next].0 == start {
                next += 1;
            }
            let end = ordered_entries
                .get(next)
                .map(|(entry, _)| *entry)
                .unwrap_or(module.instructions.len())
                .min(module.instructions.len());
            for (_, index) in &ordered_entries[offset..next] {
                function_ranges[*index] = (start, end);
            }
            offset = next;
        }
        let mut uses = vec![false; function_count];
        let mut creators: Vec<Vec<usize>> = vec![Vec::new(); function_count];
        let mut worklist = Vec::new();
        for (index, (start, end)) in function_ranges.iter().copied().enumerate() {
            let Some(body) = module.instructions.get(start..end) else {
                continue;
            };
            for instruction in body {
                match instruction {
                    Ir3Instruction::LoadSuper { .. } => {
                        if !uses[index] {
                            uses[index] = true;
                            worklist.push(index);
                        }
                    }
                    Ir3Instruction::CreateClosure { function_index, .. }
                    | Ir3Instruction::CreateArrowClosure { function_index, .. }
                    | Ir3Instruction::CreateAsyncFunction { function_index, .. }
                    | Ir3Instruction::CreateAsyncArrowClosure { function_index, .. } => {
                        let child = *function_index as usize;
                        if child < function_count {
                            creators[child].push(index);
                        }
                    }
                    _ => {}
                }
            }
        }
        // A function uses `super` when a closure it creates does: walk the
        // creation edges backwards from every direct reader (iterative, and
        // a cycle through recursion stops at visited functions).
        while let Some(current) = worklist.pop() {
            for &creator in &creators[current] {
                if !uses[creator] {
                    uses[creator] = true;
                    worklist.push(creator);
                }
            }
        }
        let uses = std::sync::Arc::new(uses);
        let mut memo = self.lexical_super_functions.borrow_mut();
        if memo.len() >= PROTOTYPE_OWNER_MEMO_ENTRIES {
            memo.remove(0);
        }
        memo.push((module.header.clone(), std::sync::Arc::clone(&uses)));
        Ok(uses)
    }

    pub(super) fn capture_current_lexical_super_metadata(
        &self,
        module: &Ir3Module,
        function_index: u32,
    ) -> Result<Option<ClosureLexicalSuperMetadata>, InterpreterError> {
        if !self.function_uses_lexical_super(module, function_index)? {
            return Ok(None);
        }
        let Some(frame) = self
            .call_stack
            .last()
            .filter(|frame| frame.super_home_object.is_some())
        else {
            return Ok(None);
        };
        self.check_temporary_memory_budget(
            Self::estimate_label_bytes(&frame.super_label)
                .saturating_add(Self::estimate_value_bytes(&frame.this_value))
                .saturating_add(Self::estimate_label_bytes(&frame.this_label)),
        )?;
        Ok(Some(ClosureLexicalSuperMetadata {
            home_object: frame
                .super_home_object
                .expect("filtered concise-method frame has a HomeObject"),
            definition_label: frame.super_label.clone(),
            this_value: frame.this_value.clone(),
            this_label: frame.this_label.clone(),
        }))
    }

    /// The running code's `this`: the current frame's, or at top level
    /// (bd-9vouw.47) the active CommonJS module's `exports`, else one
    /// per-realm ordinary object. Node runs a script file as a CommonJS
    /// module, whose top-level `this` is `module.exports`.
    /// ES2020 9.2.1.2 OrdinaryCallBindThis steps 5-6 for non-strict code
    /// (bd-9vouw.118): undefined or null is the global object (as
    /// `globalThis` resolves in the running code, so generated functions get
    /// their realm's), a primitive its wrapper object (ToObject). With no
    /// global object bound, the value is left alone.
    pub(super) fn sloppy_this_value(&mut self, value: Value) -> Result<Value, InterpreterError> {
        match value {
            Value::Undefined | Value::Null => {
                let global = match self.resolve_runtime_name_binding("globalThis") {
                    Some(binding) => Some(binding.state()?.value.clone()),
                    None => None,
                };
                Ok(global
                    .filter(|global| global.is_object_like())
                    .unwrap_or(value))
            }
            Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Str(_)
            | Value::BigInt(_)
            | Value::Symbol(_) => Ok(Value::Object(self.alloc_primitive_wrapper(value)?)),
            other => Ok(other),
        }
    }

    pub(super) fn current_this_binding(&mut self) -> Result<(Value, Label), InterpreterError> {
        if let Some(frame) = self.call_stack.last() {
            return Ok((frame.this_value.clone(), frame.this_label.clone()));
        }
        if let Some(context) = &self.active_cjs_context {
            return Ok((Value::Object(context.exports_object), Label::Public));
        }
        // Top-level code (bd-9vouw.417): a module's `this` is undefined
        // (ES2020 15.2.1.17.4 GetThisBinding). A script's is the global
        // object, which the parser's SloppyThis conversion makes of this
        // undefined for every top-level script read, its arrows' included.
        Ok((Value::Undefined, Label::Public))
    }

    pub(super) fn clone_closure_lexical_this_binding(
        &self,
        callee: &Value,
        already_owned_temporary_bytes: u64,
    ) -> Result<Option<(Value, Label)>, InterpreterError> {
        let closure_id = match callee {
            Value::Closure(closure_id) | Value::AsyncFunction(closure_id) => closure_id,
            _ => return Ok(None),
        };
        // bd-asw4m.3: an arrow closure always binds its creation-time lexical
        // `this`, regardless of receiver or caller frame.
        if let Some((this_value, this_label)) = self.arrow_lexical_this.get(closure_id) {
            self.check_temporary_memory_budget(
                already_owned_temporary_bytes
                    .saturating_add(Self::estimate_value_bytes(this_value))
                    .saturating_add(Self::estimate_label_bytes(this_label)),
            )?;
            return Ok(Some((this_value.clone(), this_label.clone())));
        }
        let Some(metadata) = self.closure_lexical_super_metadata.get(closure_id) else {
            return Ok(None);
        };
        self.check_temporary_memory_budget(
            already_owned_temporary_bytes
                .saturating_add(Self::estimate_value_bytes(&metadata.this_value))
                .saturating_add(Self::estimate_label_bytes(&metadata.this_label)),
        )?;
        Ok(Some((
            metadata.this_value.clone(),
            metadata.this_label.clone(),
        )))
    }

    pub(super) fn clone_receiver_this_binding(
        &self,
        receiver_value: &Value,
        receiver_register: u32,
        already_owned_temporary_bytes: u64,
    ) -> Result<(Value, Label), InterpreterError> {
        let receiver_label = self.get_register_label(receiver_register)?;
        self.check_temporary_memory_budget(
            already_owned_temporary_bytes
                .saturating_add(Self::estimate_value_bytes(receiver_value))
                .saturating_add(Self::estimate_label_bytes(receiver_label)),
        )?;
        Ok((receiver_value.clone(), receiver_label.clone()))
    }

    pub(super) fn closure_super_binding(
        &self,
        callee: &Value,
        callee_register: u32,
        already_owned_temporary_bytes: u64,
    ) -> Result<(Value, Label, Option<ObjectId>), InterpreterError> {
        let closure_id = match callee {
            Value::Closure(closure_id) | Value::AsyncFunction(closure_id) => closure_id,
            _ => return Ok((Value::Undefined, Label::Public, None)),
        };
        let (home_object, definition_label) =
            if let Some(metadata) = self.closure_method_metadata.get(closure_id) {
                (metadata.home_object, &metadata.definition_label)
            } else if let Some(metadata) = self.closure_lexical_super_metadata.get(closure_id) {
                (metadata.home_object, &metadata.definition_label)
            } else {
                return Ok((Value::Undefined, Label::Public, None));
            };
        let home = self
            .heap
            .get(home_object.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: home_object.0 })?;
        let super_value = home.prototype.map(Value::Object).unwrap_or(Value::Null);
        let mut dominant_label = definition_label;
        if let Some(home_label) = self.binary_storage_label_ref(home_object) {
            if home_label > dominant_label {
                dominant_label = home_label;
            }
        }
        if let Some(home_label) = self.object_mutation_labels.get(&home_object) {
            if home_label > dominant_label {
                dominant_label = home_label;
            }
        }
        let callee_label = self.get_register_label(callee_register)?;
        if callee_label > dominant_label {
            dominant_label = callee_label;
        }
        self.check_temporary_memory_budget(
            already_owned_temporary_bytes
                .saturating_add(Self::estimate_label_bytes(dominant_label)),
        )?;
        Ok((super_value, dominant_label.clone(), Some(home_object)))
    }

    pub(super) fn constructor_prototype_for_value(
        &mut self,
        module: &Ir3Module,
        value: &Value,
    ) -> Result<ObjectId, InterpreterError> {
        match self.constructor_prototype_other_than_default(module, value)? {
            Some(prototype) => Ok(prototype),
            None => self.default_constructor_prototype_for_value(module, value),
        }
    }

    /// GetPrototypeFromConstructor's answer when it is not `value`'s default
    /// prototype object: a reassigned `prototype` property, or a callable
    /// proxy's `prototype`. `None` means the default answers.
    pub(super) fn constructor_prototype_other_than_default(
        &mut self,
        module: &Ir3Module,
        value: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        if let Some((value, _)) = self.constructor_prototype_override(module, value)? {
            return self.constructed_prototype_link(module, value).map(Some);
        }
        // A callable proxy newTarget (bd-9vouw.132): GetPrototypeFromConstructor
        // reads its `prototype` through [[Get]], so its get trap or its target
        // answers. `new P(...)` of a trapless proxy over a proxy passes P on.
        if Self::is_callable_proxy(value)
            || matches!(value, Value::BuiltinFunction(builtin)
                if matches!(builtin.kind,
                    BuiltinFunctionKind::GeneratedFunction | BuiltinFunctionKind::BoundFunction))
        {
            let key = RuntimePropertyKey::String(JsString::from("prototype"));
            let prototype = self.get_v(module, value, &key)?;
            return self.constructed_prototype_link(module, prototype).map(Some);
        }
        Ok(None)
    }

    /// GetPrototypeFromConstructor step 3-4 (ES2020 9.1.14) for a
    /// `prototype` value read from the constructor: an object is the link,
    /// and so is a function, through its own-property backing object
    /// (prototype_link_for_value; `F.prototype = fn; new F()` inherits fn's
    /// properties and `fn.isPrototypeOf` holds, Test262 S13.2.2_A1);
    /// anything else falls back to %Object.prototype%.
    pub(super) fn constructed_prototype_link(
        &mut self,
        module: &Ir3Module,
        prototype: Value,
    ) -> Result<ObjectId, InterpreterError> {
        match prototype {
            Value::Object(prototype) => Ok(prototype),
            function if function.is_callable() => {
                match self.prototype_link_for_value(Some(module), &function)? {
                    Some(Some(link)) => Ok(link),
                    _ => self.ensure_builtin_prototype("Object"),
                }
            }
            _ => self.ensure_builtin_prototype("Object"),
        }
    }

    pub(super) fn default_constructor_prototype_for_value(
        &mut self,
        module: &Ir3Module,
        value: &Value,
    ) -> Result<ObjectId, InterpreterError> {
        let foreign_owner = self.foreign_closure_module(value, module)?;
        let owner_module = foreign_owner.as_deref().unwrap_or(module);
        match value {
            Value::Function(function_index) => {
                self.ensure_function_prototype(owner_module, *function_index)
            }
            Value::Closure(closure_id)
                if !self.closure_method_metadata.contains_key(closure_id) =>
            {
                self.ensure_closure_prototype(owner_module, *closure_id)
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::GeneratedFunction =>
            {
                self.ensure_generated_function_prototype(builtin)
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::NativeHttpFunction =>
            {
                self.native_http_function_prototype(&builtin.module_specifier)
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::NativeChildProcessFunction =>
            {
                self.native_child_process_function_prototype(&builtin.module_specifier)
            }
            Value::BuiltinFunction(builtin) if builtin.kind.is_constructible() => {
                self.ensure_builtin_prototype(builtin.display_name())
            }
            _ => Err(InterpreterError::TypeError {
                expected: "constructor function".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    /// The [[HomeObject]] of a class constructor whose body reads `super`
    /// (ES2020 14.6.13 step 12: the constructor's HomeObject is its
    /// prototype object), so `super.x`, `super.m()` and an arrow's `super`
    /// look up from that prototype's [[Prototype]], as a method's do.
    /// Constructor frames had none, so LoadSuper read the frame's
    /// `super_value`, the parent constructor: `super.m()` called the
    /// parent's static `m`, and a base class's `super.x` threw
    /// (bd-9vouw.363). `super(...)` still takes the parent constructor from
    /// `super_value`. `default_prototype` is the constructor's
    /// (default_constructor_prototype_for_value).
    pub(super) fn constructor_super_home_object(
        &self,
        module: &Ir3Module,
        function_index: u32,
        default_prototype: ObjectId,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        if !self.function_uses_lexical_super(module, function_index)? {
            return Ok(None);
        }
        Ok(Some(default_prototype))
    }

    pub(super) fn derived_constructor_metadata(
        &mut self,
        module: &Ir3Module,
        constructor: &Value,
    ) -> Result<(bool, bool, Value, Label), InterpreterError> {
        let prototype = self.default_constructor_prototype_for_value(module, constructor)?;
        self.derived_constructor_metadata_of_prototype(prototype)
    }

    /// derived_constructor_metadata for a constructor whose default
    /// prototype object is already resolved. The [[Construct]] paths
    /// resolve it once and read the metadata, the instance field list and
    /// the HomeObject from it (bd-9vouw.504): an entry in
    /// `function_prototypes` is only ever inserted, never replaced.
    pub(super) fn derived_constructor_metadata_of_prototype(
        &self,
        prototype: ObjectId,
    ) -> Result<(bool, bool, Value, Label), InterpreterError> {
        let object = self
            .heap
            .get(prototype.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: prototype.0 })?;
        Ok((
            object.is_derived_constructor,
            object.is_default_derived_constructor,
            object
                .derived_constructor_parent
                .as_deref()
                .cloned()
                .unwrap_or(Value::Undefined),
            object
                .derived_constructor_parent_label
                .as_deref()
                .cloned()
                .unwrap_or(Label::Public),
        ))
    }

    /// The instance field list of a class constructor (recorded on its
    /// default prototype object by `builtin:ClassDefineField`), if it has
    /// fields.
    pub(super) fn class_instance_field_list(&self, default_prototype: ObjectId) -> Option<Value> {
        self.heap
            .get(default_prototype.0 as usize)
            .and_then(|object| object.class_fields.as_deref().cloned())
    }

    /// Replace an object's engine-private class field list, charging the
    /// slot's footprint.
    /// The primitive a wrapper object holds, if `object_id` is one.
    /// bd-9vouw.17: a function's own property names are its backing
    /// object's (`length` and `name` first), plus the dedicated `prototype`
    /// after them when it has one. The backing object's label goes to the
    /// pending HostCall result.
    pub(super) fn function_own_property_keys(
        &mut self,
        module: Option<&Ir3Module>,
        function: &Value,
        depth: u32,
    ) -> Result<Vec<Value>, InterpreterError> {
        let mut names = match self.own_property_holder(module, function, true)? {
            Some(backing) => {
                self.join_pending_hostcall_stream_label(backing)?;
                self.proxy_aware_own_property_keys(module, backing, depth)?
            }
            None => Vec::new(),
        };
        let prototype = Value::str("prototype");
        let materialized = self.function_has_intrinsic_prototype(function);
        if self.object_own_property_contains(function, &prototype)
            && (materialized || !names.contains(&prototype))
        {
            if materialized {
                // Lazy storage can be seeded after a constructor's static
                // methods. Its intrinsic prototype predates those methods.
                names.retain(|key| *key != prototype);
            }
            // Integer keys come first, then string keys in creation order:
            // `length` and `name`, then `prototype` (made before any static
            // member), so `prototype` goes after the leading integer keys
            // and `length`/`name` (ES2020 9.1.11.1).
            let (length, name) = (Value::str("length"), Value::str("name"));
            let position = names
                .iter()
                .position(|key| {
                    *key != length
                        && *key != name
                        && !matches!(key, Value::Str(text)
                            if Self::canonical_array_index_key(text.as_ref()).is_some())
                })
                .unwrap_or(names.len());
            names.insert(position, prototype);
        }
        Ok(names)
    }

    pub(super) fn function_own_property_names(
        &mut self,
        module: Option<&Ir3Module>,
        function: &Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        Ok(self
            .function_own_property_keys(module, function, 0)?
            .into_iter()
            .filter(|key| matches!(key, Value::Str(_)))
            .collect())
    }

    /// The same intrinsic descriptor used by reads, definitions and Proxy
    /// invariants. Ordinary property storage owns materialized attributes,
    /// including a class's readonly prototype and a frozen function.
    pub(super) fn function_prototype_descriptor_fields(
        &mut self,
        module: Option<&Ir3Module>,
        function: &Value,
    ) -> Result<Option<PropertyDescriptorFields>, InterpreterError> {
        let Some(module) = module else {
            return Ok(None);
        };
        if !self.object_own_property_contains(function, &Value::str("prototype")) {
            return Ok(None);
        }
        if let Some(backing) = self.function_own_property_object(module, function)? {
            self.join_pending_hostcall_stream_label(backing)?;
            if let Some(fields) = self.ordinary_own_property_descriptor_fields(
                backing,
                &RuntimePropertyKey::String(JsString::from("prototype")),
            ) {
                return Ok(Some(fields));
            }
        }
        let prototype_override = self.constructor_prototype_override(module, function)?;
        let (value, mut writable) = if let Some((value, label)) = prototype_override {
            self.join_into_pending_hostcall_result_label(Some(label))?;
            self.observe_scoped_callback_result()?;
            (value, true)
        } else {
            match function {
                Value::Function(index) => (
                    self.function_property_value(module, *index, "prototype")?,
                    true,
                ),
                Value::Closure(id) => {
                    (self.closure_property_value(module, *id, "prototype")?, true)
                }
                Value::GeneratorFunction(_) | Value::AsyncGeneratorFunction(_) => (
                    self.generator_function_prototype(module, function)?
                        .unwrap_or(Value::Undefined),
                    true,
                ),
                // bd-9vouw.17: a built-in constructor's `prototype` is not
                // writable (ES2020 19.1.2.19, 20.1.2.15, ...).
                Value::BuiltinFunction(builtin) => {
                    if builtin.kind == BuiltinFunctionKind::GeneratedFunction {
                        return Ok(Some(PropertyDescriptorFields {
                            value: Some(Value::Object(
                                self.ensure_generated_function_prototype(builtin)?,
                            )),
                            writable: Some(true),
                            enumerable: Some(false),
                            configurable: Some(false),
                            ..PropertyDescriptorFields::default()
                        }));
                    }
                    let value = match Self::materialized_global_prototype_name(builtin) {
                        Some(name) => self.builtin_prototype_value(name)?,
                        None if builtin.kind == BuiltinFunctionKind::StandardConstructor => {
                            self.standard_constructor_property(builtin, "prototype")?
                        }
                        None => return Ok(None),
                    };
                    (value, false)
                }
                _ => return Ok(None),
            }
        };
        if let Some(backing) = self.function_own_property_object(module, function)? {
            let object = self
                .heap
                .get(backing.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: backing.0 })?;
            writable &= !object.is_frozen;
        }
        Ok(Some(PropertyDescriptorFields {
            value: Some(value),
            writable: Some(writable),
            enumerable: Some(false),
            configurable: Some(false),
            ..PropertyDescriptorFields::default()
        }))
    }

    pub(super) fn function_prototype_descriptor(
        &mut self,
        module: Option<&Ir3Module>,
        function: &Value,
    ) -> Result<Value, InterpreterError> {
        match self.function_prototype_descriptor_fields(module, function)? {
            Some(fields) => self.descriptor_object_from_fields(&fields, false),
            None => Ok(Value::Undefined),
        }
    }

    /// A callable target's backing stores `name` and `length`, while its
    /// intrinsic `prototype` lives in the constructor-prototype registry.
    /// Invariants and public reflection must observe the same descriptor.
    pub(super) fn function_backing_virtual_descriptor_fields(
        &mut self,
        module: Option<&Ir3Module>,
        backing: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<Option<PropertyDescriptorFields>, InterpreterError> {
        if key.as_str() != Some("prototype") {
            return Ok(None);
        }
        if self
            .heap
            .get(backing.0 as usize)
            .is_some_and(|object| object.properties.contains_key("prototype"))
        {
            return Ok(None);
        }
        let Some(module) = module else {
            return Ok(None);
        };
        let Some(function) = self.function_value_for_backing(module, backing) else {
            return Ok(None);
        };
        self.function_prototype_descriptor_fields(Some(module), &function)
    }

    /// The Symbol keys of a function's own properties (bd-9vouw.109), in
    /// creation order.
    pub(super) fn function_own_property_symbols(
        &mut self,
        module: Option<&Ir3Module>,
        function: &Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        Ok(self
            .function_own_property_keys(module, function, 0)?
            .into_iter()
            .filter(|key| matches!(key, Value::Symbol(_)))
            .collect())
    }

    pub(super) fn primitive_wrapper_value(&self, object_id: ObjectId) -> Option<&Value> {
        self.heap
            .get(object_id.0 as usize)
            .and_then(|object| object.primitive_value.as_deref())
    }

    /// ES2020 7.1.18 ToObject of a primitive: a new wrapper object whose
    /// prototype is its type's (bd-9vouw.73).
    pub(super) fn alloc_primitive_wrapper(
        &mut self,
        value: Value,
    ) -> Result<ObjectId, InterpreterError> {
        let type_name = match &value {
            Value::Bool(_) => "Boolean",
            Value::Int(_) | Value::Float(_) => "Number",
            Value::Str(_) => "String",
            Value::BigInt(_) => "BigInt",
            Value::Symbol(_) => "Symbol",
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "primitive to wrap".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let prototype = self.ensure_builtin_prototype(type_name)?;
        let object_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.set_primitive_wrapper_value(object_id, value)?;
        Ok(object_id)
    }

    /// Give `object_id` the [[NumberData]] (StringData, BooleanData, ...)
    /// `value`, charging its bytes.
    /// Brand `object_id` as a built-in or host object of kind `brand`
    /// (bd-9vouw.150), charging the name's bytes.
    pub(super) fn set_object_brand(
        &mut self,
        object_id: ObjectId,
        brand: &str,
    ) -> Result<(), InterpreterError> {
        let index = object_id.0 as usize;
        let previous = self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let previous_bytes = Self::estimate_brand_bytes(previous.brand.as_deref());
        let brand = JsString::from(brand);
        self.apply_memory_component_delta(
            previous_bytes,
            Self::estimate_brand_bytes(Some(&brand)),
        )?;
        self.mutate_heap(|heap| heap[index].brand = Some(Box::new(brand)));
        Ok(())
    }

    pub(super) fn estimate_brand_bytes(brand: Option<&JsString>) -> u64 {
        brand.map_or(0, |brand| brand.len() as u64)
    }

    pub(super) fn set_primitive_wrapper_value(
        &mut self,
        object_id: ObjectId,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let index = object_id.0 as usize;
        let previous = self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let previous_bytes = Self::estimate_heap_object_bytes(previous);
        let mut projected = previous.clone();
        projected.primitive_value = Some(Box::new(value));
        let projected_bytes = Self::estimate_heap_object_bytes(&projected);
        self.apply_memory_component_delta(previous_bytes, projected_bytes)?;
        self.mutate_heap(|heap| heap[index] = projected);
        Ok(())
    }

    /// ES2020 thisNumberValue / thisStringValue / thisBooleanValue /
    /// thisBigIntValue / thisSymbolValue: a builtin of Number.prototype
    /// (String, Boolean, BigInt, Symbol) called on a wrapper object of that
    /// type works on the wrapped primitive.
    pub(super) fn this_primitive_receiver(
        &self,
        builtin: &BuiltinFunction,
        object_id: ObjectId,
    ) -> Value {
        // Every builtin called on an object passes through here: decide from
        // the owner before touching the heap.
        let owner = builtin.spec_owner();
        if !matches!(
            owner,
            Some(
                "Number.prototype"
                    | "String.prototype"
                    | "Boolean.prototype"
                    | "BigInt.prototype"
                    | "Symbol.prototype"
            )
        ) {
            return Value::Object(object_id);
        }
        match (owner, self.primitive_wrapper_value(object_id)) {
            (Some("Number.prototype"), Some(value @ (Value::Int(_) | Value::Float(_))))
            | (Some("String.prototype"), Some(value @ Value::Str(_)))
            | (Some("Boolean.prototype"), Some(value @ Value::Bool(_)))
            | (Some("BigInt.prototype"), Some(value @ Value::BigInt(_)))
            | (Some("Symbol.prototype"), Some(value @ Value::Symbol(_))) => value.clone(),
            _ => Value::Object(object_id),
        }
    }

    /// A string's enumerable own index properties, which come first in its
    /// [[OwnPropertyKeys]] (ES2020 9.4.3.3): each index with its code unit.
    /// The key and value strings are charged before they are built.
    pub(super) fn string_index_entries(
        &self,
        text: &JsString,
    ) -> Result<Vec<(JsString, Value)>, InterpreterError> {
        let length = text.utf16_len();
        self.check_temporary_memory_budget(
            u64::try_from(length)
                .unwrap_or(u64::MAX)
                .saturating_mul(MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_mul(2) + 24),
        )?;
        Ok(text
            .encode_utf16()
            .enumerate()
            .map(|(index, unit)| {
                (
                    JsString::from(index.to_string()),
                    Value::Str(JsString::from_code_units(&[unit])),
                )
            })
            .collect())
    }

    /// The integer-indexed own properties that are not heap entries, in index
    /// order: a String wrapper's code units ([`Self::string_index_entries`])
    /// or a typed array's elements (ES2020 9.4.5.6); empty otherwise.
    pub(super) fn indexed_own_entries(
        &self,
        object_id: ObjectId,
    ) -> Result<Vec<(JsString, Value)>, InterpreterError> {
        if let Some(Value::Str(text)) = self.primitive_wrapper_value(object_id) {
            return self.string_index_entries(text);
        }
        let Some(view) = self.typed_array_view_for_object(object_id)? else {
            return Ok(Vec::new());
        };
        self.check_temporary_memory_budget(
            u64::try_from(view.length)
                .unwrap_or(u64::MAX)
                .saturating_mul(MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(24)),
        )?;
        let values = self.typed_array_values_in_range(&view, 0, view.length)?;
        Ok(values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (JsString::from(index.to_string()), value))
            .collect())
    }

    /// A String wrapper's own properties: its code-unit indices and `length`
    /// (ES2020 9.4.3 String exotic objects).
    pub(super) fn string_wrapper_own_property(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Option<Value> {
        match self.primitive_wrapper_value(object_id) {
            Some(Value::Str(text)) => Self::string_own_property_value(text, key),
            _ => None,
        }
    }

    /// The descriptor of a String's own `key` (ES2020 9.4.3.1
    /// StringGetOwnProperty, 9.4.3.4 StringCreate): a code-unit index below
    /// the length, enumerable, and `length`, not enumerable, both read-only
    /// and non-configurable; `None` for any other key (bd-9vouw.356).
    pub(super) fn string_own_property_descriptor(
        &mut self,
        text: &JsString,
        key: &RuntimePropertyKey,
    ) -> Result<Option<Value>, InterpreterError> {
        let Some(name) = key.as_str() else {
            return Ok(None);
        };
        let Some(value) = Self::string_own_property_value(text, name) else {
            return Ok(None);
        };
        let fields = PropertyDescriptorFields {
            value: Some(value),
            writable: Some(false),
            get: None,
            set: None,
            enumerable: Some(name != "length"),
            configurable: Some(false),
        };
        self.descriptor_object_from_fields(&fields, true).map(Some)
    }

    pub(super) fn set_class_fields_slot(
        &mut self,
        object_id: ObjectId,
        fields: Option<Value>,
    ) -> Result<(), InterpreterError> {
        let index = object_id.0 as usize;
        let previous = self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let previous_bytes = Self::estimate_heap_object_bytes(previous);
        let mut projected = previous.clone();
        projected.class_fields = fields.map(Box::new);
        let projected_bytes = Self::estimate_heap_object_bytes(&projected);
        self.apply_memory_component_delta(previous_bytes, projected_bytes)?;
        self.mutate_heap(|heap| heap[index] = projected);
        Ok(())
    }

    /// `builtin:ClassDefineField(target, key, function, kind)`: append the
    /// element `[kind, key, function]` to `target`'s list and give the
    /// function `target` as its [[HomeObject]], so `super.x` in a field
    /// initializer, private method or static block resolves like it does in a
    /// method of the same class. A private accessor half is named `get #x` /
    /// `set #x` (ES2022 15.4.5).
    pub(super) fn record_class_field(
        &mut self,
        target: ObjectId,
        kind: i64,
        key: Value,
        function: Value,
        definition_label: Label,
    ) -> Result<(), InterpreterError> {
        let closure_id = match &function {
            Value::Closure(closure_id)
            | Value::GeneratorFunction(closure_id)
            | Value::AsyncFunction(closure_id)
            | Value::AsyncGeneratorFunction(closure_id) => *closure_id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "fresh closure for a class element".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if self.closure_method_metadata.contains_key(&closure_id) {
            return Err(InterpreterError::TypeError {
                expected: "unregistered class element function".to_string(),
                got: format!("closure#{closure_id} already has a [[HomeObject]]"),
            });
        }
        let property_key = self.executable_property_key_from_value(&key);
        let name = self.inferred_method_name(&property_key);
        let name = match kind {
            crate::lowering_pipeline::CLASS_ELEMENT_PRIVATE_GETTER => {
                JsString::from("get ").concat(&name)
            }
            crate::lowering_pipeline::CLASS_ELEMENT_PRIVATE_SETTER => {
                JsString::from("set ").concat(&name)
            }
            _ => name,
        };
        let metadata = ClosureMethodMetadata {
            home_object: target,
            name,
            definition_label,
        };
        let metadata_bytes = Self::estimate_closure_method_metadata_entry_bytes(&metadata);
        self.apply_memory_component_delta(0, metadata_bytes)?;
        self.closure_method_metadata.insert(closure_id, metadata);

        let entry = [Value::Int(kind), key, function];
        // Append to the target's list in place. Copying it into a new array
        // for every element made defining a class of N elements O(N^2)
        // (2,000 private fields took 2.9 s to run, bd-9vouw.304).
        if let Some(Value::Object(list)) = self
            .heap
            .get(target.0 as usize)
            .and_then(|object| object.class_fields.as_deref().cloned())
        {
            let start = self.array_like_length(list)?;
            for (offset, value) in entry.into_iter().enumerate() {
                self.set_object_property(list, (start + offset).to_string(), value)?;
            }
            let length = start + 3;
            self.set_object_property(
                list,
                "length".to_string(),
                Value::Int(i64::try_from(length).unwrap_or(i64::MAX)),
            )?;
            let cached_length = u32::try_from(length).ok();
            self.mutate_heap(|heap| {
                if let Some(object) = heap.get_mut(list.0 as usize) {
                    object.cached_dense_length = cached_length;
                }
            });
            return Ok(());
        }
        let list = self.alloc_array_from_values(&entry)?;
        self.set_class_fields_slot(target, Some(Value::Object(list)))
    }

    /// ES2022 InitializeInstanceElements (7.3.34) / the static elements of
    /// ClassDefinitionEvaluation (15.7.14 steps 34-35): first give `target`
    /// every private method and accessor of `fields`, then run each field
    /// initializer and static block in declaration order with `receiver` as
    /// `this`. A public field's value becomes an own enumerable, writable,
    /// configurable data property of `target` (CreateDataPropertyOrThrow: a
    /// non-extensible target throws), a private field's a private element;
    /// the value's IFC label is stored with it.
    pub(super) fn run_class_field_initializers(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        target: ObjectId,
        fields: &Value,
    ) -> Result<(), InterpreterError> {
        use crate::lowering_pipeline::{
            CLASS_ELEMENT_FIELD, CLASS_ELEMENT_NAMED_FIELD, CLASS_ELEMENT_PRIVATE_GETTER,
            CLASS_ELEMENT_PRIVATE_METHOD, CLASS_ELEMENT_PRIVATE_SETTER, CLASS_ELEMENT_STATIC_BLOCK,
        };
        let Value::Object(list) = fields else {
            return Ok(());
        };
        let entries = self.array_like_values(*list)?;
        let elements = entries.as_chunks::<3>().0;

        let mut methods: Vec<(SymbolId, PrivateElement)> = Vec::new();
        for [kind, key, function] in elements {
            let (Value::Int(kind), Value::Symbol(name)) = (kind, key) else {
                continue;
            };
            let function = function.clone();
            let element = match *kind {
                CLASS_ELEMENT_PRIVATE_METHOD => PrivateElement::Method { function },
                CLASS_ELEMENT_PRIVATE_GETTER => PrivateElement::Accessor {
                    get: Some(function),
                    set: None,
                },
                CLASS_ELEMENT_PRIVATE_SETTER => PrivateElement::Accessor {
                    get: None,
                    set: Some(function),
                },
                _ => continue,
            };
            // A getter and a setter of one name form one accessor.
            if let PrivateElement::Accessor {
                get: new_get,
                set: new_set,
            } = &element
                && let Some((_, PrivateElement::Accessor { get, set })) =
                    methods.iter_mut().find(|(existing, _)| existing == name)
            {
                if new_get.is_some() {
                    get.clone_from(new_get);
                }
                if new_set.is_some() {
                    set.clone_from(new_set);
                }
                continue;
            }
            methods.push((*name, element));
        }
        for (name, element) in methods {
            self.add_private_element(target, name, element)?;
        }

        for [kind, key, function] in elements {
            let Value::Int(kind) = kind else {
                continue;
            };
            if !matches!(
                *kind,
                CLASS_ELEMENT_FIELD | CLASS_ELEMENT_NAMED_FIELD | CLASS_ELEMENT_STATIC_BLOCK
            ) {
                continue;
            }
            let (value, label) = self.invoke_inline_method_call_with_argument_label(
                Some(module),
                function.clone(),
                receiver.clone(),
                Vec::new(),
                None,
            )?;
            if *kind == CLASS_ELEMENT_STATIC_BLOCK {
                continue;
            }
            if let Value::Symbol(name) = key
                && self.symbol_state.is_class_private_name(*name)
            {
                self.add_private_element(target, *name, PrivateElement::Field { value, label })?;
                continue;
            }
            let key = self.executable_property_key_from_value(key);
            if *kind == CLASS_ELEMENT_NAMED_FIELD {
                self.name_anonymous_function_value(module, &value, &key)?;
            }
            self.run_pre_runtime_property_access_hook(module, target, &key)?;
            self.set_own_runtime_property_label(target, &key, &label)?;
            self.set_object_runtime_property(target, key.clone(), value)?;
            self.set_own_property_attributes(target, &key, PropertyAttributes::DEFAULT)?;
        }
        Ok(())
    }

    /// SetFunctionName (ES2020 9.2.11) of a fresh anonymous function value
    /// by a property key ("[desc]" for a symbol), through its own-property
    /// backing: an object literal entry or a class field whose computed key
    /// names it (bd-9vouw.237). A function whose own name is no longer ""
    /// (a class with a `static name` member) keeps it; a value that is not a
    /// user function is left alone.
    pub(super) fn name_anonymous_function_value(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        if !matches!(
            value,
            Value::Closure(_)
                | Value::GeneratorFunction(_)
                | Value::AsyncFunction(_)
                | Value::AsyncGeneratorFunction(_)
        ) {
            return Ok(());
        }
        let Some(backing) = self.ensure_function_own_property_object(module, value)? else {
            return Ok(());
        };
        let anonymous = matches!(
            self.heap
                .get(backing.0 as usize)
                .and_then(|object| object.properties.get("name")),
            Some(Value::Str(name)) if name.utf16_len() == 0
        );
        if anonymous {
            let name_key = RuntimePropertyKey::String(JsString::from("name"));
            let name = Value::Str(self.inferred_method_name(key));
            self.set_object_runtime_property(backing, name_key.clone(), name)?;
            self.set_own_property_attributes(backing, &name_key, FUNCTION_NAME_LENGTH_ATTRIBUTES)?;
        }
        Ok(())
    }

    /// The description of a class private name, `#x`, for error messages.
    pub(super) fn private_name_text(&self, name: SymbolId) -> String {
        self.symbol_description(name)
            .map(|description| description.to_string())
            .unwrap_or_else(|| "#<private>".to_string())
    }

    /// ES2022 PrivateFieldAdd / PrivateMethodOrAccessorAdd (7.3.28-29): give
    /// `target` the private element `name`. An object that already has it
    /// (a base constructor returned an object that was initialized before)
    /// throws a TypeError. Integrity levels do not apply: private elements
    /// are not properties.
    pub(super) fn add_private_element(
        &mut self,
        target: ObjectId,
        name: SymbolId,
        element: PrivateElement,
    ) -> Result<(), InterpreterError> {
        let index = target.0 as usize;
        let object = self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: target.0 })?;
        if object.private_elements.contains_key(&name) {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "an object not yet initialized with private member {}",
                    self.private_name_text(name)
                ),
                got: "an object that already has it".to_string(),
            });
        }
        for value in element.values() {
            validate_symbol_value(&self.symbol_state, value).map_err(|got| {
                InterpreterError::TypeError {
                    expected: "resolved Symbol value".to_string(),
                    got,
                }
            })?;
        }
        self.apply_memory_component_delta(0, Self::estimate_private_element_bytes(&element))?;
        self.mutate_heap(|heap| heap[index].private_elements.insert(name, element));
        Ok(())
    }

    /// The object holding `value`'s [[PrivateElements]]: an object itself, a
    /// function's own-property backing object (none before it has one), no
    /// primitive.
    pub(super) fn private_elements_holder(
        &self,
        module: &Ir3Module,
        value: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        match value {
            Value::Object(object_id) => Ok(Some(*object_id)),
            Value::Function(_)
            | Value::Closure(_)
            | Value::GeneratorFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::BuiltinFunction(_) => self.function_own_property_object(module, value),
            _ => Ok(None),
        }
    }

    /// The private element `name` of `value`, with its holder.
    pub(super) fn find_private_element(
        &self,
        module: &Ir3Module,
        value: &Value,
        name: SymbolId,
    ) -> Result<Option<(ObjectId, PrivateElement)>, InterpreterError> {
        let Some(holder) = self.private_elements_holder(module, value)? else {
            return Ok(None);
        };
        Ok(self
            .heap
            .get(holder.0 as usize)
            .and_then(|object| object.private_elements.get(&name))
            .map(|element| (holder, element.clone())))
    }

    /// ES2022 PrivateGet (7.3.31): `value.#x`. A field reads its value and
    /// label, a method is itself, an accessor calls its getter.
    pub(super) fn private_get(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        name: SymbolId,
    ) -> Result<(Value, Label), InterpreterError> {
        match self.find_private_element(module, value, name)? {
            Some((_, PrivateElement::Field { value, label })) => Ok((value, label)),
            Some((_, PrivateElement::Method { function })) => Ok((function, Label::Public)),
            Some((
                _,
                PrivateElement::Accessor {
                    get: Some(getter), ..
                },
            )) => self.invoke_inline_method_call_with_argument_label(
                Some(module),
                getter,
                value.clone(),
                Vec::new(),
                None,
            ),
            Some((_, PrivateElement::Accessor { get: None, .. })) => {
                Err(InterpreterError::TypeError {
                    expected: format!("a getter for {}", self.private_name_text(name)),
                    got: "an accessor defined without one".to_string(),
                })
            }
            None => Err(InterpreterError::TypeError {
                expected: format!(
                    "an object whose class declared private member {}",
                    self.private_name_text(name)
                ),
                got: value.type_name().to_string(),
            }),
        }
    }

    /// ES2022 PrivateSet (7.3.32): `value.#x = new_value`. A field is
    /// updated (its label with it), a method is read-only, an accessor calls
    /// its setter.
    pub(super) fn private_set(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        name: SymbolId,
        new_value: Value,
        new_label: Label,
    ) -> Result<(), InterpreterError> {
        match self.find_private_element(module, value, name)? {
            Some((holder, previous @ PrivateElement::Field { .. })) => {
                validate_symbol_value(&self.symbol_state, &new_value).map_err(|got| {
                    InterpreterError::TypeError {
                        expected: "resolved Symbol value".to_string(),
                        got,
                    }
                })?;
                let element = PrivateElement::Field {
                    value: new_value,
                    label: new_label,
                };
                self.apply_memory_component_delta(
                    Self::estimate_private_element_bytes(&previous),
                    Self::estimate_private_element_bytes(&element),
                )?;
                let index = holder.0 as usize;
                self.mutate_heap(|heap| heap[index].private_elements.insert(name, element));
                Ok(())
            }
            Some((_, PrivateElement::Method { .. })) => Err(InterpreterError::TypeError {
                expected: format!("a writable private member {}", self.private_name_text(name)),
                got: "a private method".to_string(),
            }),
            Some((
                _,
                PrivateElement::Accessor {
                    set: Some(setter), ..
                },
            )) => {
                self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    setter,
                    value.clone(),
                    vec![new_value],
                    Some(new_label),
                )?;
                Ok(())
            }
            Some((_, PrivateElement::Accessor { set: None, .. })) => {
                Err(InterpreterError::TypeError {
                    expected: format!("a setter for {}", self.private_name_text(name)),
                    got: "an accessor defined without one".to_string(),
                })
            }
            None => Err(InterpreterError::TypeError {
                expected: format!(
                    "an object whose class declared private member {}",
                    self.private_name_text(name)
                ),
                got: value.type_name().to_string(),
            }),
        }
    }

    /// ES2022 `#x in value` (13.10.1): whether `value` has the private
    /// element; a primitive `value` throws a TypeError.
    pub(super) fn private_in(
        &self,
        module: &Ir3Module,
        value: &Value,
        name: SymbolId,
    ) -> Result<bool, InterpreterError> {
        let is_object = matches!(
            value,
            Value::Object(_)
                | Value::Function(_)
                | Value::Closure(_)
                | Value::GeneratorFunction(_)
                | Value::AsyncFunction(_)
                | Value::AsyncGeneratorFunction(_)
                | Value::BuiltinFunction(_)
        );
        if !is_object {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "an object on the right of `{} in`",
                    self.private_name_text(name)
                ),
                got: value.type_name().to_string(),
            });
        }
        Ok(self.find_private_element(module, value, name)?.is_some())
    }

    /// `key` when it is a class private name (`o.#x`, `#x in o`).
    pub(super) fn class_private_name_key(&self, key: &Value) -> Option<SymbolId> {
        match key {
            Value::Symbol(symbol) if self.symbol_state.is_class_private_name(*symbol) => {
                Some(*symbol)
            }
            _ => None,
        }
    }

    /// Run the instance fields of the derived constructor on top of the call
    /// stack once its super() has initialized `this` (ES2022 15.7.14
    /// SuperCall step 11 InitializeInstanceElements).
    pub(super) fn run_derived_class_instance_fields(
        &mut self,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let Some(frame) = self.call_stack.last_mut() else {
            return Ok(());
        };
        let Some(fields) = frame.class_instance_fields.take() else {
            return Ok(());
        };
        let Value::Object(object_id) = frame.this_value else {
            return Ok(());
        };
        let module = module.ok_or_else(|| InterpreterError::InternalError {
            details: "class field initializers need the executing module".to_string(),
        })?;
        self.run_class_field_initializers(module, Value::Object(object_id), object_id, &fields)
    }

    pub(super) fn register_derived_constructor_metadata(
        &mut self,
        module: &Ir3Module,
        constructor: &Value,
        parent: Value,
        parent_label: Label,
        default_constructor: bool,
    ) -> Result<(), InterpreterError> {
        // A standard constructor reached as a value (`const M = Map`, a name
        // that `typeof` made dynamic, `extends (Base || Error)`) is recorded
        // by its canonical name, as the lowering records `extends Map`
        // itself, so construction takes the same built-in-parent path
        // instead of failing with "expected constructor function".
        // ES2020 14.6.13 step 6.g.i: a superclass other than null must be a
        // constructor; an arrow, a generator, an async function or a method
        // is not (bd-9vouw.205). A builtin parent arrives as its name.
        if !matches!(parent, Value::Null | Value::Str(_)) && !self.is_constructible_value(&parent) {
            let received = self.node_received_description(&parent);
            return Err(self.throw_js_error(
                "TypeError",
                format!("Class extends value {received} is not a constructor or null"),
            ));
        }
        let parent = match &parent {
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::StandardConstructor =>
            {
                match Self::standard_constructor_name(builtin) {
                    Ok(name) if LOWERED_BUILTIN_CLASS_PARENTS.contains(&name) => Value::str(name),
                    _ => parent,
                }
            }
            _ => parent,
        };
        let prototype = self.default_constructor_prototype_for_value(module, constructor)?;
        let index = prototype.0 as usize;
        let previous = self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: prototype.0 })?;
        let previous_bytes = Self::estimate_heap_object_bytes(previous);
        let mut projected = previous.clone();
        projected.derived_constructor_parent = Some(Box::new(parent.clone()));
        projected.derived_constructor_parent_label = Some(Box::new(parent_label));
        projected.is_derived_constructor = true;
        projected.is_default_derived_constructor = default_constructor;
        let projected_bytes = Self::estimate_heap_object_bytes(&projected);
        self.apply_memory_component_delta(previous_bytes, projected_bytes)?;
        self.mutate_heap(|heap| heap[index] = projected);
        // bd-9vouw.24: [[GetPrototypeOf]] of a derived class constructor is its
        // parent, so the child's own-property object inherits from the
        // parent's: inherited statics resolve, and `super.s()` in a static
        // method (whose [[HomeObject]] is that object) finds the parent's.
        if let Some(child_backing) =
            self.ensure_function_own_property_object(module, constructor)?
            && let Some(parent_backing) =
                self.ensure_function_own_property_object(module, &parent)?
            && child_backing != parent_backing
            && !self.chain_contains_object(parent_backing, child_backing)
        {
            let child_index = child_backing.0 as usize;
            self.mutate_heap(|heap| heap[child_index].prototype = Some(parent_backing));
        }
        Ok(())
    }

    /// Whether `needle` is `object_id` or on its prototype chain.
    pub(super) fn chain_contains_object(&self, object_id: ObjectId, needle: ObjectId) -> bool {
        let mut current = Some(object_id);
        let mut depth = 0u32;
        while let Some(id) = current {
            if id == needle {
                return true;
            }
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return false;
            }
            current = self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.prototype);
            depth += 1;
        }
        false
    }

    /// Whether `key` is an own property of `object_id` or of an object on its
    /// prototype chain (no accessor or proxy invocation).
    pub(super) fn chain_contains_runtime_property(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> bool {
        let mut current = Some(object_id);
        let mut depth = 0u32;
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return false;
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                return false;
            };
            if object.contains_own_runtime_property(key) {
                return true;
            }
            current = self.observable_prototype_link(object, id);
            depth += 1;
        }
        false
    }

    /// The guest-visible value of an intrinsic prototype. The heap keeps
    /// ObjectId links for property storage, while %Function.prototype%
    /// exposes the callable value owning that same storage (bd-9vouw.346).
    pub(super) fn builtin_prototype_value(
        &mut self,
        name: &str,
    ) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype(name)?;
        Ok(self.prototype_value_for_link(None, Some(prototype)))
    }

    pub(super) fn ensure_builtin_prototype(
        &mut self,
        name: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let canonical =
            canonical_builtin_prototype_name(name).ok_or_else(|| InterpreterError::TypeError {
                expected: "known builtin constructor prototype".to_string(),
                got: name.to_string(),
            })?;
        if let Some(existing) = self.builtin_prototypes.get(canonical) {
            return Ok(*existing);
        }

        let parent = match canonical {
            "BigInt" | "Number" | "String" | "Boolean" | "Symbol" | "Function" => {
                Some(self.ensure_builtin_prototype("Object")?)
            }
            // ES2020 25.2.3, 25.7.3; ES2018 25.3.3: their [[Prototype]] is
            // %Function.prototype%.
            "GeneratorFunction" | "AsyncFunction" | "AsyncGeneratorFunction" => {
                Some(self.ensure_builtin_prototype("Function")?)
            }
            // ES2020 25.1.2, 22.1.5.2, 25.4.1: %IteratorPrototype% inherits
            // from Object.prototype, the array iterator and generator
            // prototypes from it; ES2018 25.1.3, 25.5.1: so does
            // %AsyncIteratorPrototype%, %AsyncGeneratorPrototype% from it.
            ITERATOR_PROTOTYPE | ASYNC_ITERATOR_PROTOTYPE => {
                Some(self.ensure_builtin_prototype("Object")?)
            }
            ASYNC_GENERATOR_PROTOTYPE => {
                Some(self.ensure_builtin_prototype(ASYNC_ITERATOR_PROTOTYPE)?)
            }
            ARRAY_ITERATOR_PROTOTYPE
            | MAP_ITERATOR_PROTOTYPE
            | SET_ITERATOR_PROTOTYPE
            | GENERATOR_PROTOTYPE
            | iterator_helpers::ITERATOR_HELPER_PROTOTYPE
            | iterator_helpers::WRAP_FOR_VALID_ITERATOR_PROTOTYPE
            | iterator_helpers::REGEXP_STRING_ITERATOR_PROTOTYPE => {
                Some(self.ensure_builtin_prototype(ITERATOR_PROTOTYPE)?)
            }
            "TypeError" | "RangeError" | "ReferenceError" | "SyntaxError" | "EvalError"
            | "URIError" | "AggregateError" => Some(self.ensure_builtin_prototype("Error")?),
            // ES2020 22.2.6: the concrete typed array prototypes inherit the
            // shared methods from %TypedArray.prototype%, whose own
            // [[Prototype]] is %Object.prototype% (22.2.3).
            "TypedArray" => Some(self.ensure_builtin_prototype("Object")?),
            name if TypedArrayKind::from_type_name(name).is_some() => {
                Some(self.ensure_builtin_prototype("TypedArray")?)
            }
            // Node: Buffer.prototype inherits from Uint8Array.prototype.
            "Buffer" => Some(self.ensure_builtin_prototype("Uint8Array")?),
            // DOM (bd-9vouw.170): CustomEvent.prototype inherits from
            // Event.prototype, AbortSignal's from EventTarget's, and
            // DOMException's from Error.prototype.
            "CustomEvent" => Some(self.ensure_builtin_prototype("Event")?),
            "AbortSignal" => Some(self.ensure_builtin_prototype("EventTarget")?),
            "DOMException" => Some(self.ensure_builtin_prototype("Error")?),
            _ => None,
        };
        let prototype = self.alloc_object_with_prototype(parent)?;
        self.mutate_builtin_prototypes(|bp| {
            bp.insert(canonical.to_string(), prototype);
        });
        // Number.prototype, String.prototype and Boolean.prototype are
        // themselves wrapper objects of +0, "" and false (ES2020 20.1.3,
        // 21.1.3, 19.3.3): `Number.prototype.toString(10)` is "0", not a
        // TypeError for a non-Number receiver.
        let wrapped = match canonical {
            "Number" => Some(Value::Int(0)),
            "String" => Some(Value::str("")),
            "Boolean" => Some(Value::Bool(false)),
            _ => None,
        };
        if let Some(value) = wrapped {
            self.set_primitive_wrapper_value(prototype, value)?;
        }
        // These prototypes carry an own @@toStringTag data property naming
        // the constructor (ES2020 23.1.3.13, 23.2.3.12, 24.1.4.4, 25.6.5.4,
        // ...; writable false, enumerable false, configurable true):
        // `Set.prototype[Symbol.toStringTag]` was undefined. It goes on while
        // the property map is empty (see alloc_math_global).
        if matches!(
            canonical,
            "Map"
                | "Set"
                | "WeakMap"
                | "WeakSet"
                | "Promise"
                | "ArrayBuffer"
                | "SharedArrayBuffer"
                | "DataView"
                | "Symbol"
                | "BigInt"
                | "WeakRef"
                | "FinalizationRegistry"
                | "GeneratorFunction"
                | "AsyncFunction"
                | "AsyncGeneratorFunction"
                | "URL"
                | "URLSearchParams"
                | "EventTarget"
                | "Event"
                | "CustomEvent"
                | "AbortController"
                | "AbortSignal"
                | "DOMException"
                | "Blob"
        ) {
            let key = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
            self.set_object_runtime_property(prototype, key.clone(), Value::str(canonical))?;
            self.set_own_property_attributes(
                prototype,
                &key,
                PropertyAttributes {
                    writable: false,
                    enumerable: false,
                    configurable: true,
                },
            )?;
        }
        // Symbol.prototype[@@toPrimitive] (ES2020 19.4.3.5; writable false,
        // enumerable false, configurable true): ToPrimitive of a Symbol
        // wrapper is its symbol, so ToString of the wrapper throws as for the
        // symbol itself (bd-9vouw.239). Date.prototype's (20.3.4.45, the same
        // attributes) reads the "default" hint as "string" (bd-9vouw.259).
        let to_primitive_kind = match canonical {
            "Symbol" => Some(BuiltinFunctionKind::SymbolPrototypeToPrimitive),
            "Date" => Some(BuiltinFunctionKind::DatePrototypeToPrimitive),
            _ => None,
        };
        // Function.prototype[@@hasInstance] (ES2020 19.2.3.6; not writable,
        // enumerable or configurable). `instanceof` keeps performing
        // OrdinaryHasInstance itself, which is what this intrinsic does
        // (bd-9vouw.268).
        if canonical == "Function" {
            let key = RuntimePropertyKey::Symbol(WellKnownSymbol::HasInstance.id());
            self.set_object_runtime_property(
                prototype,
                key.clone(),
                Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::FunctionPrototypeHasInstance,
                )),
            )?;
            self.set_own_property_attributes(
                prototype,
                &key,
                PropertyAttributes {
                    writable: false,
                    enumerable: false,
                    configurable: false,
                },
            )?;
            // AddRestrictedFunctionProperties (ES2020 9.2.7): `arguments`
            // and `caller` are accessors whose get and set are
            // %ThrowTypeError%, not enumerable, configurable. A strict,
            // arrow, method, class, generator, async, bound or built-in
            // function has no own ones and inherits these (bd-9vouw.272).
            let thrower = self.throw_type_error_intrinsic()?;
            for name in ["arguments", "caller"] {
                let key = RuntimePropertyKey::String(JsString::from(name));
                for kind in [AccessorKind::Get, AccessorKind::Set] {
                    self.define_accessor_property(prototype, key.clone(), thrower.clone(), kind)?;
                }
                self.set_own_property_attributes(
                    prototype,
                    &key,
                    PropertyAttributes {
                        writable: false,
                        enumerable: false,
                        configurable: true,
                    },
                )?;
            }
        }
        if let Some(kind) = to_primitive_kind {
            let key = RuntimePropertyKey::Symbol(WellKnownSymbol::ToPrimitive.id());
            self.set_object_runtime_property(
                prototype,
                key.clone(),
                Value::BuiltinFunction(BuiltinFunction::new_kind(kind)),
            )?;
            self.set_own_property_attributes(
                prototype,
                &key,
                PropertyAttributes {
                    writable: false,
                    enumerable: false,
                    configurable: true,
                },
            )?;
        }
        // %TypedArray%.prototype[@@toStringTag] is an accessor whose getter
        // answers the receiver's kind (ES2020 22.2.3.32, bd-9vouw.155):
        // safe-stable-stringify reads it with getOwnPropertyDescriptor.
        if canonical == TYPED_ARRAY_INTRINSIC {
            let key = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
            self.define_accessor_property(
                prototype,
                key.clone(),
                Value::BuiltinFunction(BuiltinFunction::prototype_getter(
                    TYPED_ARRAY_INTRINSIC,
                    prototype_getters::TYPED_ARRAY_TO_STRING_TAG,
                )),
                AccessorKind::Get,
            )?;
            self.set_own_property_attributes(
                prototype,
                &key,
                PropertyAttributes {
                    writable: false,
                    enumerable: false,
                    configurable: true,
                },
            )?;
        }
        // Each concrete TypedArray.prototype has an own BYTES_PER_ELEMENT
        // (ES2020 22.2.6.1; not writable, enumerable or configurable), as its
        // constructor does: `Int16Array.prototype.BYTES_PER_ELEMENT` was
        // undefined.
        if let Some(kind) = TypedArrayKind::from_type_name(canonical) {
            let key = RuntimePropertyKey::String(JsString::from("BYTES_PER_ELEMENT"));
            let size = i64::try_from(kind.element_size()).unwrap_or(i64::MAX);
            self.set_object_runtime_property(prototype, key.clone(), Value::Int(size))?;
            self.set_own_property_attributes(
                prototype,
                &key,
                PropertyAttributes {
                    writable: false,
                    enumerable: false,
                    configurable: false,
                },
            )?;
        }
        // Node's EventEmitter.prototype holds its methods as own enumerable
        // properties and its `constructor` (bd-9vouw.210). Instances found
        // them only through their EventEmitter brand, so an object that
        // inherits from the prototype without running the constructor
        // (`ctor.prototype = EE.prototype; new ctor()`, Object.create, a
        // mixin copying the prototype's members) had none. The methods
        // accept any object receiver.
        if canonical == "EventEmitter" {
            for name in EVENT_EMITTER_PROTOTYPE_METHODS {
                if let Some(method) = Self::collection_prototype_method("EventEmitter", name) {
                    self.set_object_runtime_property(
                        prototype,
                        RuntimePropertyKey::String(JsString::from(name)),
                        Value::BuiltinFunction(method),
                    )?;
                }
            }
            let key = RuntimePropertyKey::String(JsString::from("constructor"));
            self.set_object_runtime_property(
                prototype,
                key.clone(),
                Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::EventEmitterConstructor,
                )),
            )?;
            self.set_own_property_attributes(prototype, &key, NON_ENUMERABLE_DATA_ATTRIBUTES)?;
        }
        self.install_iteration_prototype_members(canonical, prototype)?;
        if canonical == "Array" {
            self.install_array_unscopables(prototype)?;
        }
        // %GeneratorFunction.prototype%.prototype is %GeneratorPrototype%
        // (ES2020 25.2.3.2), linked when that one is created.
        match canonical {
            "GeneratorFunction" => {
                self.ensure_builtin_prototype(GENERATOR_PROTOTYPE)?;
            }
            "AsyncGeneratorFunction" => {
                self.ensure_builtin_prototype(ASYNC_GENERATOR_PROTOTYPE)?;
            }
            _ => {}
        }
        if ERROR_PROTOTYPE_NAMES.contains(&canonical) {
            // ES2020 19.5.3.2-3 / 19.5.6.3.2-3: `name` and `message` live on
            // the prototypes, so instances inherit them and a subclass's
            // `MyError.prototype.name` is not shadowed.
            self.set_object_property(prototype, "name".to_string(), Value::str(canonical))?;
            self.set_object_property(prototype, "message".to_string(), Value::str(""))?;
            for key in ["name", "message"] {
                self.set_own_property_attributes(
                    prototype,
                    &RuntimePropertyKey::String(JsString::from(key)),
                    NON_ENUMERABLE_DATA_ATTRIBUTES,
                )?;
            }
        }
        Ok(prototype)
    }

    /// Array.prototype[@@unscopables] (ES2020 22.1.3.32 and the names later
    /// editions add): a null-prototype object whose own `true` data
    /// properties name the methods a `with` body does not resolve on an
    /// array, itself non-writable, non-enumerable and configurable.
    pub(super) fn install_array_unscopables(
        &mut self,
        prototype: ObjectId,
    ) -> Result<(), InterpreterError> {
        let list = self.alloc_object_with_prototype(None)?;
        self.store_prototype_link(list, None);
        for name in ARRAY_UNSCOPABLE_NAMES {
            self.set_object_property(list, name.to_string(), Value::Bool(true))?;
        }
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Unscopables.id());
        self.set_object_runtime_property(prototype, key.clone(), Value::Object(list))?;
        self.set_own_property_attributes(
            prototype,
            &key,
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: true,
            },
        )
    }

    /// Own members of the iteration intrinsics (ES2020 25.1.2.1, 22.1.5.2,
    /// 25.4.1; ES2018 25.5.1): %IteratorPrototype%[@@iterator] returns its
    /// receiver; %ArrayIteratorPrototype% has `next`; the generator
    /// prototypes have `next`/`return`/`throw` and a `constructor` that is
    /// their function kind's prototype, whose `prototype` they are (each
    /// non-writable, configurable). Methods are writable, configurable and
    /// not enumerable; each has an @@toStringTag. A no-op for other names.
    pub(super) fn install_iteration_prototype_members(
        &mut self,
        canonical: &str,
        prototype: ObjectId,
    ) -> Result<(), InterpreterError> {
        let method = |name: &str, kind| {
            (
                RuntimePropertyKey::String(JsString::from(name)),
                Value::BuiltinFunction(BuiltinFunction::new_kind(kind)),
            )
        };
        let (tag, members, function_kind) = match canonical {
            ITERATOR_PROTOTYPE => {
                let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
                let value = Value::BuiltinFunction(BuiltinFunction::generator_iterator_self());
                self.set_object_runtime_property(prototype, key.clone(), value)?;
                self.set_own_property_attributes(prototype, &key, NON_ENUMERABLE_DATA_ATTRIBUTES)?;
                // ES2025 27.1.4: the Iterator helpers, `constructor` and
                // @@toStringTag (data properties here; the specification's
                // are accessors) (bd-9vouw.179).
                let mut members = vec![(
                    RuntimePropertyKey::String(JsString::from("constructor")),
                    Value::BuiltinFunction(BuiltinFunction::standard_constructor("Iterator")),
                )];
                members.extend(
                    iterator_helpers::ITERATOR_HELPER_METHODS
                        .iter()
                        .filter(|(_, owner, _)| *owner == "Iterator.prototype")
                        .map(|(specifier, _, name)| {
                            (
                                RuntimePropertyKey::String(JsString::from(*name)),
                                iterator_helpers::helper_method(specifier),
                            )
                        }),
                );
                members.push((
                    RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id()),
                    Value::str("Iterator"),
                ));
                for (key, value) in members {
                    self.set_object_runtime_property(prototype, key.clone(), value)?;
                    self.set_own_property_attributes(
                        prototype,
                        &key,
                        NON_ENUMERABLE_DATA_ATTRIBUTES,
                    )?;
                }
                return Ok(());
            }
            // ES2018 25.1.3.1: its only own member, no @@toStringTag.
            ASYNC_ITERATOR_PROTOTYPE => {
                let key = RuntimePropertyKey::Symbol(WellKnownSymbol::AsyncIterator.id());
                let value = Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::AsyncGeneratorIteratorSelf,
                ));
                self.set_object_runtime_property(prototype, key.clone(), value)?;
                self.set_own_property_attributes(prototype, &key, NON_ENUMERABLE_DATA_ATTRIBUTES)?;
                return Ok(());
            }
            iterator_helpers::ITERATOR_HELPER_PROTOTYPE
            | iterator_helpers::WRAP_FOR_VALID_ITERATOR_PROTOTYPE
            | iterator_helpers::REGEXP_STRING_ITERATOR_PROTOTYPE => {
                let members = iterator_helpers::ITERATOR_HELPER_METHODS
                    .iter()
                    .filter(|(_, owner, _)| *owner == canonical)
                    .map(|(specifier, _, name)| {
                        (
                            RuntimePropertyKey::String(JsString::from(*name)),
                            iterator_helpers::helper_method(specifier),
                        )
                    })
                    .collect::<Vec<_>>();
                for (key, value) in members {
                    self.set_object_runtime_property(prototype, key.clone(), value)?;
                    self.set_own_property_attributes(
                        prototype,
                        &key,
                        NON_ENUMERABLE_DATA_ATTRIBUTES,
                    )?;
                }
                // %WrapForValidIteratorPrototype% has no @@toStringTag.
                if canonical == iterator_helpers::WRAP_FOR_VALID_ITERATOR_PROTOTYPE {
                    return Ok(());
                }
                if canonical == iterator_helpers::REGEXP_STRING_ITERATOR_PROTOTYPE {
                    ("RegExp String Iterator", Vec::new(), None)
                } else {
                    ("Iterator Helper", Vec::new(), None)
                }
            }
            ARRAY_ITERATOR_PROTOTYPE => (
                "Array Iterator",
                vec![method("next", BuiltinFunctionKind::IteratorNext)],
                None,
            ),
            MAP_ITERATOR_PROTOTYPE => (
                "Map Iterator",
                vec![method("next", BuiltinFunctionKind::IteratorNext)],
                None,
            ),
            SET_ITERATOR_PROTOTYPE => (
                "Set Iterator",
                vec![method("next", BuiltinFunctionKind::IteratorNext)],
                None,
            ),
            GENERATOR_PROTOTYPE => (
                "Generator",
                vec![
                    method("next", BuiltinFunctionKind::GeneratorNext),
                    method("return", BuiltinFunctionKind::GeneratorReturn),
                    method("throw", BuiltinFunctionKind::GeneratorThrow),
                ],
                Some("GeneratorFunction"),
            ),
            ASYNC_GENERATOR_PROTOTYPE => (
                "AsyncGenerator",
                vec![
                    method("next", BuiltinFunctionKind::AsyncGeneratorNext),
                    method("return", BuiltinFunctionKind::AsyncGeneratorReturn),
                    method("throw", BuiltinFunctionKind::AsyncGeneratorThrow),
                ],
                Some("AsyncGeneratorFunction"),
            ),
            _ => return Ok(()),
        };
        for (key, value) in members {
            self.set_object_runtime_property(prototype, key.clone(), value)?;
            self.set_own_property_attributes(prototype, &key, NON_ENUMERABLE_DATA_ATTRIBUTES)?;
        }
        let read_only = PropertyAttributes {
            writable: false,
            enumerable: false,
            configurable: true,
        };
        let tag_key = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
        self.set_object_runtime_property(prototype, tag_key.clone(), Value::str(tag))?;
        self.set_own_property_attributes(prototype, &tag_key, read_only)?;
        if let Some(function_kind) = function_kind {
            let function_prototype = self.ensure_builtin_prototype(function_kind)?;
            let constructor = RuntimePropertyKey::String(JsString::from("constructor"));
            self.set_object_runtime_property(
                prototype,
                constructor.clone(),
                Value::Object(function_prototype),
            )?;
            self.set_own_property_attributes(prototype, &constructor, read_only)?;
            let link = RuntimePropertyKey::String(JsString::from("prototype"));
            self.set_object_runtime_property(
                function_prototype,
                link.clone(),
                Value::Object(prototype),
            )?;
            self.set_own_property_attributes(function_prototype, &link, read_only)?;
        }
        Ok(())
    }

    pub(super) fn builtin_subclass_ancestor_name(
        &self,
        prototype: ObjectId,
    ) -> Result<Option<String>, InterpreterError> {
        let prototype_names: BTreeMap<ObjectId, String> = self
            .builtin_prototypes
            .iter()
            .map(|(name, object_id)| (*object_id, name.clone()))
            .collect();
        let mut current = self
            .heap
            .get(prototype.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: prototype.0 })?
            .prototype;
        let mut depth = 0u32;
        let mut visited = BTreeSet::new();
        visited.insert(prototype);

        while let Some(object_id) = current {
            if let Some(name) = prototype_names.get(&object_id) {
                return Ok(Some(name.clone()));
            }
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(object_id) {
                return Ok(None);
            }
            current = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
                .prototype;
            depth += 1;
        }

        Ok(None)
    }

    /// `super(...)` of a class extending Array (ES2020 22.1.1): one number
    /// argument is the length of an empty array, any other arguments are
    /// its elements; the instance is already an array with new.target's
    /// prototype. It got neither elements nor a `length`: `class T extends
    /// Array {}; new T(1, 2).length` was undefined (only `super(...xs)` took
    /// the spread path). Base constructors whose prototype merely inherits
    /// Array.prototype do not run this.
    pub(super) fn initialize_array_subclass_instance(
        &mut self,
        object_id: ObjectId,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let values = self.call_arguments(args)?;
        if let [length @ (Value::Int(_) | Value::Float(_))] = values.as_slice() {
            let length = length.clone();
            return self.set_object_property(object_id, "length".to_string(), length);
        }
        for (index, value) in values.iter().cloned().enumerate() {
            self.set_object_property(object_id, index.to_string(), value)?;
        }
        let length = i64::try_from(values.len()).unwrap_or(i64::MAX);
        self.set_object_property(object_id, "length".to_string(), Value::Int(length))?;
        let cached_length = u32::try_from(length).unwrap_or(u32::MAX);
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(object_id.0 as usize) {
                object.cached_dense_length = Some(cached_length);
            }
        });
        Ok(())
    }

    pub(super) fn initialize_builtin_subclass_instance(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        builtin_name: &str,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        match builtin_name {
            "AggregateError" => self.initialize_aggregate_error(module, object_id, args)?,
            "Error" | "TypeError" | "RangeError" | "ReferenceError" | "SyntaxError"
            | "EvalError" | "URIError" => {
                let message = self.error_message_from_args(module, args)?;
                self.initialize_error_object(object_id, message)?;
                self.install_error_cause(object_id, args)?;
            }
            "Map" => {
                let entries_id = self.alloc_object_with_prototype(None)?;
                self.set_object_brand(object_id, "Map")?;
                self.set_collection_storage(object_id, entries_id)?;
                let iterable = self.arg_or_undefined(args, 0)?;
                if !matches!(iterable, Value::Undefined | Value::Null) {
                    match self.collection_seed_adder(module, object_id, "Map")? {
                        None => {
                            self.seed_map_entries_from_iterable(module, entries_id, iterable)?
                        }
                        Some(adder) => self
                            .seed_collection_with_adder(module, object_id, adder, true, iterable)?,
                    }
                }
            }
            "Set" => {
                let values_id = self.alloc_object_with_prototype(None)?;
                self.set_object_brand(object_id, "Set")?;
                self.set_collection_storage(object_id, values_id)?;
                let iterable = self.arg_or_undefined(args, 0)?;
                if !matches!(iterable, Value::Undefined | Value::Null) {
                    match self.collection_seed_adder(module, object_id, "Set")? {
                        None => {
                            self.seed_set_values_from_iterable(module, values_id, iterable, false)?
                        }
                        Some(adder) => self.seed_collection_with_adder(
                            module, object_id, adder, false, iterable,
                        )?,
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The `message` argument of an Error constructor: `None` when absent or
    /// `undefined` (ES2020 19.5.1.1 step 3), else ToString(message), so a
    /// Symbol is a TypeError and a throwing toString / valueOf /
    /// @@toPrimitive propagates. Objects used the engine's own non-calling
    /// conversion (`new Error(Symbol())` succeeded).
    pub(super) fn error_message_from_args(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Option<String>, InterpreterError> {
        if args.count == 0 {
            return Ok(None);
        }
        Ok(match self.read_reg(args.start)? {
            Value::Undefined => None,
            Value::Str(s) => Some(s.to_string()),
            other => Some(
                self.scoped_conversion(|this| this.conversion_to_string(module, other))?
                    .to_string(),
            ),
        })
    }

    /// Rest-parameter binding (bd-zs4d5): if the callee declares a rest param at
    /// `rest_param_index`, replace that positional slot in `arg_vals` with an
    /// Array of ALL trailing args (`args[rest_idx..args.count]`). Called after
    /// the per-call fixed-arity collection; the existing param-destructure path
    /// then binds the rest name to that array register. Empty rest => `[]`.
    /// bd-9vouw.25: when `function`'s entry instruction is the `arguments`
    /// marker, build the unmapped arguments object from the caller's full
    /// argument registers (`args`, still in the caller's frame) and stage it
    /// for the callee frame about to be pushed.
    pub(super) fn stage_arguments_object(
        &mut self,
        module: &Ir3Module,
        function: &crate::ir_contract::Ir3FunctionDesc,
        function_index: u32,
        callee: &Value,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let uses_arguments = matches!(
            module.instructions.get(function.entry as usize),
            Some(Ir3Instruction::HostCall { capability, .. })
                if capability.0 == crate::lowering_pipeline::ARGUMENTS_OBJECT_CAPABILITY
        );
        if !uses_arguments {
            return Ok(());
        }
        let mut values = Vec::with_capacity(args.count as usize);
        let mut label = Label::Public;
        for offset in 0..args.count {
            let register =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            values.push(self.read_reg(register)?);
            label = label.join(self.get_register_label(register)?);
        }
        // bd-9vouw.272: a sloppy function with a simple parameter list gets
        // a `callee` data property (CreateMappedArgumentsObject), any other
        // function the %ThrowTypeError% accessor.
        let callee = match module.sloppy_functions.get(&function_index) {
            Some(true) => {
                // The trampoline's raw index is private to the generated
                // module. Exposing it through arguments.callee would let it
                // escape into the caller's unrelated function table.
                let value = match (self.active_generated_function_artifact, callee) {
                    (Some(handle), Value::Function(index))
                        if self
                            .resolve_generated_function_artifact(
                                handle.owner_program_id,
                                handle.artifact_id,
                            )?
                            .function_index
                            == *index =>
                    {
                        self.check_temporary_memory_budget(
                            Self::generated_function_handle_peak_bytes(),
                        )?;
                        Value::BuiltinFunction(BuiltinFunction::generated_function(
                            handle.owner_program_id,
                            handle.artifact_id,
                        ))
                    }
                    _ => callee.clone(),
                };
                ArgumentsCallee::Function(value)
            }
            _ => ArgumentsCallee::ThrowTypeError,
        };
        let object = self.alloc_arguments_object(&values, callee)?;
        self.pending_arguments_object = Some((
            self.call_stack.len().saturating_add(1),
            Value::Object(object),
            label,
        ));
        Ok(())
    }

    /// An arguments object (ES2020 9.4.4.6-7): indexed elements, a
    /// non-enumerable `length`, a non-enumerable own @@iterator that is
    /// %Array.prototype.values%, so `[...arguments]`, `Array.from(arguments)`
    /// and `for (const a of arguments)` iterate it, and its `callee`
    /// (bd-9vouw.272). Sloppy, simple-parameter functions attach their
    /// initialized parameter cells at function entry (bd-9vouw.281).
    pub(super) fn alloc_arguments_object(
        &mut self,
        values: &[Value],
        callee: ArgumentsCallee,
    ) -> Result<ObjectId, InterpreterError> {
        let object = self.alloc_object_with_prototype(None)?;
        // Its builtinTag is "Arguments" (ES2020 19.1.3.6 step 7):
        // is-arguments and deep-equal tell it apart by
        // `Object.prototype.toString` (bd-9vouw.234).
        self.set_object_brand(object, "Arguments")?;
        for (index, value) in values.iter().enumerate() {
            self.set_object_property(object, index.to_string(), value.clone())?;
        }
        self.set_object_property(
            object,
            "length".to_string(),
            Value::Int(i64::try_from(values.len()).unwrap_or(i64::MAX)),
        )?;
        let iterator_key = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
        self.set_object_runtime_property(
            object,
            iterator_key.clone(),
            Value::BuiltinFunction(BuiltinFunction::array_values()),
        )?;
        let hidden = PropertyAttributes {
            writable: true,
            enumerable: false,
            configurable: true,
        };
        self.set_own_property_attributes(
            object,
            &RuntimePropertyKey::String(JsString::from("length")),
            hidden,
        )?;
        self.set_own_property_attributes(object, &iterator_key, hidden)?;
        let callee_key = RuntimePropertyKey::String(JsString::from("callee"));
        match callee {
            // ES2020 9.4.4.7 step 22: writable, not enumerable, configurable.
            ArgumentsCallee::Function(function) => {
                self.set_object_runtime_property(object, callee_key.clone(), function)?;
                self.set_own_property_attributes(object, &callee_key, hidden)?;
            }
            // ES2020 9.4.4.6 step 8: get and set are %ThrowTypeError%, not
            // enumerable or configurable.
            ArgumentsCallee::ThrowTypeError => {
                let thrower = self.throw_type_error_intrinsic()?;
                for kind in [AccessorKind::Get, AccessorKind::Set] {
                    self.define_accessor_property(
                        object,
                        callee_key.clone(),
                        thrower.clone(),
                        kind,
                    )?;
                }
                self.set_own_property_attributes(
                    object,
                    &callee_key,
                    PropertyAttributes {
                        writable: false,
                        enumerable: false,
                        configurable: false,
                    },
                )?;
            }
            ArgumentsCallee::Omitted => {}
        }
        Ok(object)
    }

    /// %ThrowTypeError% (ES2020 9.2.9.1): one function per realm (every
    /// value of the kind is the same function), whose `length` (0) and
    /// `name` ("") are neither writable nor configurable and which is not
    /// extensible, so it is frozen. Its own-property object is made so the
    /// first time it is handed out (to a strict arguments object's `callee`,
    /// or to Function.prototype's `caller` and `arguments`, bd-9vouw.272).
    pub(super) fn throw_type_error_intrinsic(&mut self) -> Result<Value, InterpreterError> {
        let builtin = BuiltinFunction::new_kind(BuiltinFunctionKind::ThrowTypeError);
        let key = Self::builtin_function_own_property_key(&builtin)?;
        let backing = match self.function_prototypes.get(&key) {
            Some(existing) => *existing,
            None => {
                let backing = self.alloc_object_with_prototype(None)?;
                self.mutate_function_prototypes(|entries| entries.insert(key, backing));
                self.builtin_function_backings = true;
                for (name, value) in [("length", Value::Int(0)), ("name", Value::str(""))] {
                    let name = RuntimePropertyKey::String(JsString::from(name));
                    self.set_object_runtime_property(backing, name, value)?;
                }
                backing
            }
        };
        if self
            .heap
            .get(backing.0 as usize)
            .is_some_and(HeapObject::extensible)
        {
            for key in ["length", "name"] {
                self.set_own_property_attributes(
                    backing,
                    &RuntimePropertyKey::String(JsString::from(key)),
                    PropertyAttributes {
                        writable: false,
                        enumerable: false,
                        configurable: false,
                    },
                )?;
            }
            self.mutate_heap(|heap| {
                if let Some(object) = heap.get_mut(backing.0 as usize) {
                    object.is_non_extensible = true;
                }
            });
        }
        Ok(Value::BuiltinFunction(builtin))
    }

    pub(super) fn apply_rest_param(
        &mut self,
        arg_vals: &mut Vec<Value>,
        rest_param_index: Option<u32>,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let Some(rest_idx) = rest_param_index else {
            return Ok(());
        };
        let mut elements = Vec::new();
        let mut i = rest_idx;
        while i < args.count {
            let reg = args
                .start
                .checked_add(i)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
            elements.push(self.read_reg(reg)?);
            i = i.checked_add(1).unwrap_or(args.count);
        }
        let len = u32::try_from(elements.len()).unwrap_or(u32::MAX);
        let array_id = self.alloc_array_with_prototype(None)?;
        for (j, value) in elements.into_iter().enumerate() {
            self.set_object_property(array_id, j.to_string(), value)?;
        }
        self.set_object_property(array_id, "length".to_string(), Value::Int(i64::from(len)))?;
        let array_index = array_id.0 as usize;
        self.mutate_heap(|heap| {
            if let Some(obj) = heap.get_mut(array_index) {
                obj.cached_dense_length = Some(len);
            }
        });
        let rest_slot = rest_idx as usize;
        while arg_vals.len() <= rest_slot {
            arg_vals.push(Value::Undefined);
        }
        arg_vals.truncate(rest_slot + 1);
        arg_vals[rest_slot] = Value::Object(array_id);
        Ok(())
    }

    /// Label-file twin of [`Self::apply_rest_param`]. A rest array depends on
    /// every trailing argument, so its register receives their lattice join.
    pub(super) fn apply_rest_param_labels(
        &self,
        arg_labels: &mut Vec<Label>,
        rest_param_index: Option<u32>,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let Some(rest_idx) = rest_param_index else {
            return Ok(());
        };
        let mut rest_label = Label::Public;
        let mut i = rest_idx;
        while i < args.count {
            let reg = args
                .start
                .checked_add(i)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
            rest_label = rest_label.join(self.get_register_label(reg)?);
            i = i.checked_add(1).unwrap_or(args.count);
        }
        let rest_slot = rest_idx as usize;
        if arg_labels.len() <= rest_slot {
            arg_labels.resize(rest_slot + 1, Label::Public);
        }
        arg_labels.truncate(rest_slot + 1);
        arg_labels[rest_slot] = rest_label;
        Ok(())
    }

    /// Resolve a property read on a function value. Functions are objects whose
    /// `prototype` is the (lazily-created) object that `new`-constructed
    /// instances inherit from — and it is where class instance methods are
    /// attached at class-definition time (`C.prototype.m = ...`). Reading
    /// `C.prototype` therefore MUST return the same object the `Construct`
    /// handler links instances to via [`Self::ensure_function_prototype`], so
    /// that `new C().m()` resolves `m` up the prototype chain (bd-62un6).
    /// Other properties are not modelled on the function object and read as
    /// `undefined`.
    pub(super) fn function_property_value(
        &mut self,
        module: &Ir3Module,
        func_idx: u32,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        // bd-9vouw.272: see closure_property_value.
        if matches!(key, "caller" | "arguments")
            && self.is_sloppy_ordinary_function(module, &Value::Function(func_idx))?
        {
            return Ok(Value::Null);
        }
        if let Some(value) = Self::function_prototype_property(key) {
            return Ok(value);
        }
        if key == "prototype" {
            if let Some((value, _)) =
                self.constructor_prototype_override(module, &Value::Function(func_idx))?
            {
                return Ok(value);
            }
            Ok(Value::Object(
                self.ensure_function_prototype(module, func_idx)?,
            ))
        } else {
            match Self::function_name_or_length(module, func_idx, key) {
                Some(value) => Ok(value),
                None => self.builtin_parent_static(module, Value::Function(func_idx), key),
            }
        }
    }

    /// bd-9vouw.17: `name` and `length` of an ordinary function, from its IR3
    /// descriptor. `length` counts the parameters before a rest parameter;
    /// an anonymous function (no descriptor name) reads `""`.
    pub(super) fn function_name_or_length(
        module: &Ir3Module,
        func_idx: u32,
        key: &str,
    ) -> Option<Value> {
        let desc = module.function_table.get(func_idx as usize)?;
        match key {
            "name" => Some(Value::str(desc.name.as_deref().unwrap_or(""))),
            // ExpectedArgumentCount: parameters before a rest parameter or
            // the first one with an initializer (bd-9vouw.134).
            "length" => Some(Value::Int(i64::from(
                module
                    .function_lengths
                    .get(&func_idx)
                    .copied()
                    .unwrap_or_else(|| desc.rest_param_index.unwrap_or(desc.arity)),
            ))),
            _ => None,
        }
    }

    pub(super) fn closure_property_value(
        &mut self,
        module: &Ir3Module,
        closure_id: u32,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        // bd-9vouw.272: Node's sloppy ordinary functions answer null for
        // their own `caller` and `arguments`; every other function reads
        // Function.prototype's %ThrowTypeError% accessors. Both the
        // GetProperty instruction and [[Get]] (function_own_get) ask here.
        if matches!(key, "caller" | "arguments")
            && self.is_sloppy_ordinary_function(module, &Value::Closure(closure_id))?
        {
            return Ok(Value::Null);
        }
        if let Some(value) = Self::function_prototype_property(key) {
            return Ok(value);
        }
        if key == "prototype" {
            if let Some((value, _)) =
                self.constructor_prototype_override(module, &Value::Closure(closure_id))?
            {
                return Ok(value);
            }
            if self.arrow_lexical_this.contains_key(&closure_id) {
                return Ok(Value::Undefined);
            }
        }
        // A closure's descriptor lives in the module that created it: a
        // `new Function` body or a required module has its own function
        // table, and the caller's entry at the same index is another function.
        let foreign_owner = self.foreign_closure_module(&Value::Closure(closure_id), module)?;
        let owner_module = foreign_owner.as_deref().unwrap_or(module);
        if let Some(metadata) = self.closure_method_metadata.get(&closure_id) {
            return Ok(match key {
                "name" => Value::Str(metadata.name.clone()),
                // Class methods are DefineMethod closures too (bd-9vouw.24);
                // their `length` is the parameter count like any function.
                "length" => {
                    let func_idx = self.closure_function_index(closure_id)?;
                    Self::function_name_or_length(owner_module, func_idx, key)
                        .unwrap_or(Value::Undefined)
                }
                "prototype" => Value::Undefined,
                _ => Value::Undefined,
            });
        }
        if key == "prototype" {
            Ok(Value::Object(
                self.ensure_closure_prototype(module, closure_id)?,
            ))
        } else {
            let func_idx = self.closure_function_index(closure_id)?;
            match Self::function_name_or_length(owner_module, func_idx, key) {
                Some(value) => Ok(value),
                None => self.builtin_parent_static(owner_module, Value::Closure(closure_id), key),
            }
        }
    }

    /// A static a class inherits from a builtin parent (`class L extends
    /// Array {}; L.from`). The class's own statics and those of class parents
    /// live on backing objects that are searched before this; a builtin
    /// parent's statics are served by its constructor, so the parent chain is
    /// walked to it. Only classes with a derived-constructor record are
    /// walked: the lookup never allocates a prototype for a plain function.
    pub(super) fn builtin_parent_static(
        &mut self,
        module: &Ir3Module,
        constructor: Value,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        let mut current = constructor;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            match self.derived_constructor_parent(module, &current) {
                Some(Value::BuiltinFunction(builtin))
                    if builtin.kind == BuiltinFunctionKind::StandardConstructor =>
                {
                    return self.standard_constructor_property(&builtin, key);
                }
                // bd-9vouw.137: Promise and Date keep their statics on a
                // property object (`class P extends Promise {}; P.resolve`).
                Some(Value::BuiltinFunction(builtin)) => {
                    let Some(property_object) = Self::builtin_function_property_object(&builtin)
                    else {
                        return Ok(Value::Undefined);
                    };
                    return self.proxy_aware_get_runtime_property(
                        Some(module),
                        property_object,
                        &RuntimePropertyKey::String(JsString::from(key)),
                        Value::BuiltinFunction(builtin),
                        0,
                    );
                }
                Some(parent @ (Value::Closure(_) | Value::Function(_))) => current = parent,
                _ => return Ok(Value::Undefined),
            }
        }
        Ok(Value::Undefined)
    }

    /// The parent a derived class records (`class C extends P`): a class,
    /// function or built-in constructor value. `None` for anything that is
    /// not a derived class, and for a built-in parent recorded by a name
    /// that is not a standard constructor global. Never allocates.
    pub(super) fn derived_constructor_parent(
        &self,
        module: &Ir3Module,
        constructor: &Value,
    ) -> Option<Value> {
        let prototype = match constructor {
            Value::Closure(id) => self
                .function_prototypes
                .get(&(self.prototype_owner_ids(module).closure, *id))
                .copied(),
            Value::Function(index) => self
                .function_prototypes
                .get(&(self.prototype_owner_ids(module).function, *index))
                .copied(),
            _ => None,
        }?;
        let parent = self
            .heap
            .get(prototype.0 as usize)
            .filter(|object| object.is_derived_constructor)
            .and_then(|object| object.derived_constructor_parent.as_deref().cloned())?;
        match parent {
            Value::Str(name) => {
                let name = name.to_string();
                STANDARD_CONSTRUCTOR_GLOBALS
                    .iter()
                    .copied()
                    .find(|candidate| *candidate == name)
                    .map(|name| Value::BuiltinFunction(BuiltinFunction::standard_constructor(name)))
            }
            parent => Some(parent),
        }
    }

    pub(super) fn is_species_key(key: &RuntimePropertyKey) -> bool {
        matches!(key, RuntimePropertyKey::Symbol(symbol) if *symbol == WellKnownSymbol::Species.id())
    }

    /// bd-9vouw.94: built-in constructors whose `get [Symbol.species]()`
    /// returns `this` (ES2020 22.1.2.5, 22.2.2.4, 23.1.2.2, 23.2.2.2,
    /// 24.1.3.3, 24.2.3.2, 25.6.4.6, 21.2.4.2). The concrete typed array
    /// constructors inherit %TypedArray%'s.
    pub(super) fn builtin_has_default_species(builtin: &BuiltinFunction) -> bool {
        if let Some(name) = Self::materialized_global_prototype_name(builtin) {
            return name == "Promise";
        }
        builtin.kind == BuiltinFunctionKind::StandardConstructor
            && Self::standard_constructor_name(builtin).is_ok_and(|name| {
                matches!(
                    name,
                    "Array"
                        | "Map"
                        | "Set"
                        | "RegExp"
                        | "ArrayBuffer"
                        | "SharedArrayBuffer"
                        | "Promise"
                ) || name == TYPED_ARRAY_INTRINSIC
                    || TypedArrayKind::from_type_name(name).is_some()
            })
    }

    /// bd-9vouw.94: Get(C, @@species) (ES2020 7.3.20 step 5) for a
    /// constructor value. An object (a proxy, a `{ [Symbol.species]: ... }`
    /// record) answers through its own [[Get]]. A class or function answers
    /// with an own or inherited static `[Symbol.species]` on its backing
    /// object (a getter sees `constructor` as `this`), else with its parent
    /// class's; a chain that reaches a built-in with the default getter gets
    /// `constructor` itself, which is what `return this` gives. Anything
    /// else has no @@species.
    pub(super) fn species_of_constructor(
        &mut self,
        module: &Ir3Module,
        constructor: &Value,
    ) -> Result<Value, InterpreterError> {
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Species.id());
        if let Value::Object(object_id) = constructor {
            return self.proxy_aware_get_runtime_property(
                Some(module),
                *object_id,
                &key,
                constructor.clone(),
                0,
            );
        }
        let mut current = constructor.clone();
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            if let Some(backing) = self.function_own_property_object(module, &current)?
                && self.chain_contains_runtime_property(backing, &key)
            {
                return self.proxy_aware_get_runtime_property(
                    Some(module),
                    backing,
                    &key,
                    constructor.clone(),
                    0,
                );
            }
            match &current {
                Value::BuiltinFunction(builtin) => {
                    return Ok(self
                        .builtin_species_value(module, builtin, constructor.clone())?
                        .unwrap_or(Value::Undefined));
                }
                Value::Closure(_) | Value::Function(_) => {
                    match self.derived_constructor_parent(module, &current) {
                        Some(parent) => current = parent,
                        None => return Ok(Value::Undefined),
                    }
                }
                _ => return Ok(Value::Undefined),
            }
        }
        Ok(Value::Undefined)
    }

    /// Whether `value` is this realm's %Array%: Array.from / Array.of with
    /// it as `this` build an ordinary Array directly.
    pub(super) fn is_intrinsic_array_constructor(value: &Value) -> bool {
        matches!(value, Value::BuiltinFunction(builtin)
            if builtin.kind == BuiltinFunctionKind::StandardConstructor
                && &*builtin.module_specifier == "Array")
    }

    /// ES2020 9.4.2.2 ArrayCreate(length). Validate before allocating or
    /// visiting source elements; a length is metadata, not a request to
    /// allocate that many slots. Keep this check in the ArrayCreate branch
    /// so custom species constructors can accept larger array-like lengths.
    pub(super) fn alloc_array_with_length(
        &mut self,
        length: u64,
    ) -> Result<ObjectId, InterpreterError> {
        if length > u64::from(u32::MAX) {
            return Err(InterpreterError::RangeError {
                message: "Invalid array length".to_string(),
            });
        }
        let result = self.alloc_array_with_prototype(None)?;
        self.set_object_property(result, "length".to_string(), Value::Int(length as i64))?;
        Ok(result)
    }

    /// bd-9vouw.94: ES2020 9.4.2.3 ArraySpeciesCreate(original, length): the
    /// result object an Array method fills. A plain array (ArrayCreate) when
    /// `original` is not an array, or its `constructor` is undefined,
    /// or that constructor's @@species is undefined, null or
    /// %Array%. Otherwise the species is constructed with `length`. A
    /// `constructor` that is not an object, a species that is not a
    /// constructor, or a construct result that is not an object is a
    /// TypeError.
    pub(super) fn array_species_result(
        &mut self,
        module: &Ir3Module,
        original: ObjectId,
        length: u64,
    ) -> Result<ObjectId, InterpreterError> {
        self.array_species_allocation(module, original, length)
            .map(|allocation| allocation.object)
    }

    /// Retain whether ArraySpeciesCreate allocated an unexposed intrinsic
    /// Array. Only that branch can bypass observable output property writes;
    /// even a plain Array returned by a custom species can be a guest alias.
    pub(super) fn array_species_allocation(
        &mut self,
        module: &Ir3Module,
        original: ObjectId,
        length: u64,
    ) -> Result<array_generic::ArraySpeciesAllocation, InterpreterError> {
        let intrinsic = |object| array_generic::ArraySpeciesAllocation {
            object,
            intrinsic: true,
        };
        if !self.generic_is_array(original)? {
            return self.alloc_array_with_length(length).map(intrinsic);
        }
        let constructor_key = RuntimePropertyKey::String(JsString::from("constructor"));
        let constructor = self.proxy_aware_get_runtime_property(
            Some(module),
            original,
            &constructor_key,
            Value::Object(original),
            0,
        )?;
        let is_intrinsic_array = |value: &Value| {
            matches!(value, Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::StandardConstructor
                    && Self::standard_constructor_name(builtin).is_ok_and(|name| name == "Array"))
        };
        if matches!(constructor, Value::Undefined) {
            return self.alloc_array_with_length(length).map(intrinsic);
        }
        if !constructor.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "object or undefined constructor for ArraySpeciesCreate".to_string(),
                got: constructor.type_name().to_string(),
            });
        }
        let species = self.species_of_constructor(module, &constructor)?;
        if matches!(species, Value::Undefined | Value::Null) || is_intrinsic_array(&species) {
            return self.alloc_array_with_length(length).map(intrinsic);
        }
        if !self.is_constructible_value(&species) {
            return Err(InterpreterError::TypeError {
                expected: "constructor @@species for ArraySpeciesCreate".to_string(),
                got: species.type_name().to_string(),
            });
        }
        let length = Value::Int(i64::try_from(length).unwrap_or(i64::MAX));
        let (result, label) =
            self.with_gc_nested_request(vec![Value::Object(original)], |core| {
                core.invoke_inline_construct_with_labels(
                    Some(module),
                    species,
                    vec![length],
                    None,
                    None,
                )
            })?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        match result {
            Value::Object(object) => Ok(array_generic::ArraySpeciesAllocation {
                object,
                intrinsic: false,
            }),
            other => Err(InterpreterError::TypeError {
                expected: "object from the @@species constructor".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// The canonical prototype a function value's [[Prototype]] defaults to:
    /// %GeneratorFunction.prototype%, %AsyncFunction.prototype% or
    /// %AsyncGeneratorFunction.prototype% for those kinds, else
    /// %Function.prototype%; `None` for a non-function.
    pub(super) fn function_intrinsic_prototype_name(value: &Value) -> Option<&'static str> {
        match value {
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::FunctionPrototype =>
            {
                Some("Object")
            }
            Value::Function(_) | Value::Closure(_) | Value::BuiltinFunction(_) => Some("Function"),
            Value::GeneratorFunction(_) => Some("GeneratorFunction"),
            Value::AsyncFunction(_) => Some("AsyncFunction"),
            Value::AsyncGeneratorFunction(_) => Some("AsyncGeneratorFunction"),
            _ => None,
        }
    }

    /// The intrinsic prototype a promise, generator, async generator or
    /// iterator value (no property storage of its own) reports and inherits
    /// from. Map, Set and String iterators are array iterators over a
    /// snapshot here, so every iterator reports %ArrayIteratorPrototype%.
    pub(super) fn exotic_intrinsic_prototype_name(&self, value: &Value) -> Option<&'static str> {
        match value {
            Value::Promise(_) => Some("Promise"),
            Value::Generator(_) => Some(GENERATOR_PROTOTYPE),
            Value::AsyncGeneratorObject(_) => Some(ASYNC_GENERATOR_PROTOTYPE),
            Value::Iterator(handle) => Some(self.iterator_intrinsic_prototype_name(*handle)),
            _ => None,
        }
    }

    /// %MapIteratorPrototype% or %SetIteratorPrototype% for a Map or Set
    /// iterator (bd-9vouw.121; they were array iterators over a copy before
    /// bd-9vouw.131), %ArrayIteratorPrototype% for the others.
    pub(super) fn iterator_intrinsic_prototype_name(&self, handle: u32) -> &'static str {
        match self.iterators.get(handle as usize) {
            Some(RuntimeIteratorState::ForOf(RuntimeForOfState {
                collection: Some(iterator),
                ..
            })) if iterator.is_map => MAP_ITERATOR_PROTOTYPE,
            Some(RuntimeIteratorState::ForOf(RuntimeForOfState {
                collection: Some(_),
                ..
            })) => SET_ITERATOR_PROTOTYPE,
            _ => ARRAY_ITERATOR_PROTOTYPE,
        }
    }

    pub(super) fn function_prototype_property(key: &str) -> Option<Value> {
        let kind = match key {
            "call" => BuiltinFunctionKind::FunctionPrototypeCall,
            "apply" => BuiltinFunctionKind::FunctionPrototypeApply,
            "bind" => BuiltinFunctionKind::FunctionPrototypeBind,
            "toString" => BuiltinFunctionKind::FunctionPrototypeToString,
            // Function.prototype inherits Object.prototype's own-property
            // queries (`fn.hasOwnProperty('x')`).
            "hasOwnProperty" | "propertyIsEnumerable" | "isPrototypeOf" => {
                return Self::object_prototype_method(key).map(Value::BuiltinFunction);
            }
            _ => return None,
        };
        Some(Value::BuiltinFunction(BuiltinFunction::new_kind(kind)))
    }

    /// Return the ordinary-property backing object for a builtin function that
    /// also acts as a mutable JavaScript object. `Date` aliases share one object
    /// so writes to `Date.now` remain visible through every reference
    /// (bd-1piai); every EventEmitter once wrapper owns a distinct object so
    /// repeated `rawListeners()` calls observe stable `.listener` state
    /// (bd-asw4m.2).
    /// The intrinsic prototype of a materialized constructor global.
    pub(super) fn materialized_global_prototype_name(
        builtin: &BuiltinFunction,
    ) -> Option<&'static str> {
        match builtin.kind {
            BuiltinFunctionKind::DateConstructor => Some("Date"),
            BuiltinFunctionKind::PromiseConstructor => Some("Promise"),
            BuiltinFunctionKind::FunctionConstructor => Some("Function"),
            // `class S extends EventEmitter` links S.prototype to it
            // (bd-9vouw.165).
            BuiltinFunctionKind::EventEmitterConstructor => Some("EventEmitter"),
            _ => None,
        }
    }

    pub(super) fn builtin_function_property_object(builtin: &BuiltinFunction) -> Option<ObjectId> {
        matches!(
            builtin.kind,
            BuiltinFunctionKind::DateConstructor
                | BuiltinFunctionKind::PromiseConstructor
                | BuiltinFunctionKind::FunctionPrototype
                | BuiltinFunctionKind::EmitterOnceWrapper
                // A callable proxy's properties are its proxy record's: every
                // property operation reaches the traps (bd-9vouw.132).
                | BuiltinFunctionKind::CallableProxy
        )
        .then_some(builtin.bound_object)
        .flatten()
        .map(ObjectId)
    }

    /// bd-9vouw.17: key of the ordinary-property backing object that holds a
    /// user function's own properties (`F.x = 1`, class `static` members).
    ///
    /// Functions are objects, but user function values carry no property
    /// storage of their own. Their backing objects live in
    /// `function_prototypes` under an owner id that is domain-separated from
    /// every prototype owner (distinct SHA-256 tag plus a per-kind byte), so
    /// they share that map's seed snapshot/restore and memory accounting and
    /// can never collide with a prototype entry. Closure-backed values
    /// (closures, generator and async functions) are keyed per closure
    /// instance, matching how their prototypes are keyed.
    pub(super) fn function_own_property_key(
        &self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<Option<(ContentHash, u32)>, InterpreterError> {
        match function {
            Value::Function(index) => Ok(Some((
                self.prototype_owner_ids(module).own_property[0],
                *index,
            ))),
            Value::Closure(id)
            | Value::GeneratorFunction(id)
            | Value::AsyncFunction(id)
            | Value::AsyncGeneratorFunction(id) => {
                let kind = match function {
                    Value::Closure(_) => 1usize,
                    Value::GeneratorFunction(_) => 2,
                    Value::AsyncFunction(_) => 3,
                    _ => 4,
                };
                let owner_module = self.foreign_closure_module(function, module)?;
                let ids = self.prototype_owner_ids(owner_module.as_deref().unwrap_or(module));
                Ok(Some((ids.own_property[kind], *id)))
            }
            // A built-in value carries no storage of its own; its backing
            // object is keyed by the built-in's identity (kind, specifier,
            // bound state). Built-ins that already own a property object
            // (`Date`, `Promise`, once wrappers) keep using it.
            Value::BuiltinFunction(builtin)
                if Self::builtin_function_property_object(builtin).is_none() =>
            {
                Self::builtin_function_own_property_key(builtin).map(Some)
            }
            // A promise, generator, async generator or iterator object has no
            // heap storage of its own either: its own properties (`p.cancel =
            // fn`, `Object.assign(promise, ...)`) live on a backing object
            // too. Their ids are the runtime's (never reused), not a
            // module's, so the owner is a constant (computed once: every
            // `p.then` read asks).
            Value::Promise(id)
            | Value::Generator(id)
            | Value::AsyncGeneratorObject(id)
            | Value::Iterator(id) => {
                static OWNERS: OnceLock<[ContentHash; 4]> = OnceLock::new();
                let owners = OWNERS.get_or_init(|| {
                    let mut digest = Sha256::new();
                    digest.update(b"FrankenEngine.ExoticObjectOwnProperties.v1");
                    let base = ContentHash::from_bytes(digest.finalize().into());
                    [6u8, 7, 8, 9].map(|kind| Self::function_own_property_owner(kind, &base))
                });
                let slot = match function {
                    Value::Promise(_) => 0,
                    Value::Generator(_) => 1,
                    Value::AsyncGeneratorObject(_) => 2,
                    _ => 3,
                };
                Ok(Some((owners[slot], *id)))
            }
            _ => Ok(None),
        }
    }

    /// bd-9vouw.272: whether `function` is an ordinary function whose code is
    /// not strict mode code (not an arrow, method, class, generator or async
    /// function): the functions with own `caller` and `arguments` in Node.
    pub(super) fn is_sloppy_ordinary_function(
        &self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<bool, InterpreterError> {
        let (owner, function_index) = match function {
            Value::Function(index) => (None, *index),
            Value::Closure(closure_id)
                if !self.closure_method_metadata.contains_key(closure_id)
                    && !self.arrow_lexical_this.contains_key(closure_id) =>
            {
                (
                    self.foreign_closure_module(function, module)?,
                    self.closure_function_index(*closure_id)?,
                )
            }
            _ => return Ok(false),
        };
        let owner = owner.as_deref().unwrap_or(module);
        Ok(owner.sloppy_functions.contains_key(&function_index)
            && owner
                .function_table
                .get(function_index as usize)
                .is_some_and(|descriptor| !descriptor.is_generator))
    }

    /// bd-9vouw.272: [[Set]] of `caller` or `arguments` on a user function
    /// that defines neither (its backing objects never received them). A
    /// sloppy ordinary function's own ones are read-only (null): a sloppy
    /// write is ignored and a strict one throws. Any other function inherits
    /// Function.prototype's accessors, so their setter (%ThrowTypeError%)
    /// runs; a write after the program deleted them, or replaced them with
    /// a data property, is an ordinary own-property write. Whether the write
    /// was handled here.
    pub(super) fn restricted_function_property_set(
        &mut self,
        module: &Ir3Module,
        function: &Value,
        key: &RuntimePropertyKey,
        value: &Value,
        strict: bool,
    ) -> Result<bool, InterpreterError> {
        if !matches!(key.as_str(), Some("caller" | "arguments")) {
            return Ok(false);
        }
        let own_object = match function {
            Value::BuiltinFunction(builtin) => {
                match Self::builtin_function_property_object(builtin) {
                    Some(property_object) => Some(property_object),
                    None => self.function_own_property_object(module, function)?,
                }
            }
            _ => self.function_own_property_object(module, function)?,
        };
        if own_object.is_some_and(|object| self.chain_contains_runtime_property(object, key)) {
            return Ok(false);
        }
        if self.is_sloppy_ordinary_function(module, function)? {
            return if strict {
                Err(Self::read_only_property_error(key))
            } else {
                Ok(true)
            };
        }
        let prototype = self.ensure_builtin_prototype("Function")?;
        let inherited = self
            .heap
            .get(prototype.0 as usize)
            .and_then(|object| object.own_runtime_property_value(key));
        let Some(accessor @ Value::Accessor { .. }) = inherited else {
            return Ok(false);
        };
        if !self.resolve_accessor_set(Some(module), accessor, function.clone(), value.clone())?
            && strict
        {
            return Err(Self::read_only_property_error(key));
        }
        Ok(true)
    }

    /// The backing-object key of a built-in function: a built-in value
    /// carries no storage of its own, so its backing object is keyed by the
    /// built-in's identity (kind, specifier, bound state). Needs no module.
    pub(super) fn builtin_function_own_property_key(
        builtin: &BuiltinFunction,
    ) -> Result<(ContentHash, u32), InterpreterError> {
        let identity =
            serde_json::to_vec(builtin).map_err(|error| InterpreterError::TypeError {
                expected: "serializable built-in function identity".to_string(),
                got: error.to_string(),
            })?;
        let mut digest = Sha256::new();
        digest.update(b"FrankenEngine.BuiltinFunctionIdentity.v1");
        digest.update(&identity);
        let base_owner = ContentHash::from_bytes(digest.finalize().into());
        Ok((Self::function_own_property_owner(5, &base_owner), 0))
    }

    /// Owner id of the backing objects of one function kind (0 = IR3
    /// function, 1 = closure, 2 = generator, 3 = async, 4 = async generator,
    /// 5 = built-in, whose base owner is its identity digest).
    pub(super) fn function_own_property_owner(kind: u8, base_owner: &ContentHash) -> ContentHash {
        let mut digest = Sha256::new();
        digest.update(b"FrankenEngine.FunctionOwnPropertyObject.v1");
        digest.update([kind]);
        digest.update(base_owner.as_bytes());
        ContentHash::from_bytes(digest.finalize().into())
    }

    /// The user function (defined by `module`) whose own-property backing
    /// object is `backing`, if any. Inverse of `function_own_property_key`.
    pub(super) fn function_value_for_backing(
        &self,
        module: &Ir3Module,
        backing: ObjectId,
    ) -> Option<Value> {
        let ((owner, id), _) = self
            .function_prototypes
            .iter()
            .find(|(_, object)| **object == backing)?;
        let value_of_kind = |ids: PrototypeOwnerIds| {
            (0u8..=4).find_map(|kind| {
                (ids.own_property[usize::from(kind)] == *owner).then_some(match kind {
                    0 => Value::Function(*id),
                    1 => Value::Closure(*id),
                    2 => Value::GeneratorFunction(*id),
                    3 => Value::AsyncFunction(*id),
                    _ => Value::AsyncGeneratorFunction(*id),
                })
            })
        };
        if let Some(value) = value_of_kind(self.prototype_owner_ids(module)) {
            return Some(value);
        }
        // A closure of another module (a parent class from another file that
        // babel's `_inherits` set as a constructor's [[Prototype]]): its owner
        // ids are its own module's. Closure ids are global, so the owner
        // module is the closure's recorded origin (bd-9vouw.209).
        let origin = self.closure_module_origins.get(id)?;
        let owner_module = self.retained_closure_module(*id, origin).ok()?;
        value_of_kind(self.prototype_owner_ids(&owner_module))
    }

    /// Existing own-property backing object for a user function, if any.
    pub(super) fn function_own_property_object(
        &self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        if matches!(function, Value::BuiltinFunction(_)) && !self.builtin_function_backings {
            return Ok(None);
        }
        Ok(self
            .function_own_property_key(module, function)?
            .and_then(|key| self.function_prototypes.get(&key).copied()))
    }

    /// Backing object for a user function, created on first write.
    pub(super) fn ensure_function_own_property_object(
        &mut self,
        module: &Ir3Module,
        function: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let Some(key) = self.function_own_property_key(module, function)? else {
            return Ok(None);
        };
        if let Some(existing) = self.function_prototypes.get(&key) {
            return Ok(Some(*existing));
        }
        let backing = self.alloc_object_with_prototype(None)?;
        self.mutate_function_prototypes(|entries| entries.insert(key, backing));
        if matches!(function, Value::BuiltinFunction(_)) {
            self.builtin_function_backings = true;
        }
        // bd-9vouw.17: from here on the backing object is the authority on the
        // function's own properties, so it starts with the standard `length`
        // and `name` (in that order, as OrdinaryFunctionCreate creates them).
        // Deleting or redefining them then behaves as on any object.
        for key in ["length", "name"] {
            if let Some(value) = self.function_standard_own_value(module, function, key)? {
                let key = RuntimePropertyKey::String(JsString::from(key));
                self.set_object_runtime_property(backing, key.clone(), value)?;
                self.set_own_property_attributes(backing, &key, FUNCTION_NAME_LENGTH_ATTRIBUTES)?;
            }
        }
        if let Value::BuiltinFunction(builtin) = function
            && builtin.kind == BuiltinFunctionKind::GeneratedFunction
        {
            let prototype = self.ensure_generated_function_prototype(builtin)?;
            let key = RuntimePropertyKey::String(JsString::from("prototype"));
            self.set_object_runtime_property(backing, key.clone(), Value::Object(prototype))?;
            self.set_own_property_attributes(
                backing,
                &key,
                PropertyAttributes {
                    writable: true,
                    enumerable: false,
                    configurable: false,
                },
            )?;
        }
        // A standard constructor's backing object also starts with its
        // `prototype` and static members, so the reflection built-ins see
        // what a read sees.
        if let Value::BuiltinFunction(builtin) = function
            && builtin.kind == BuiltinFunctionKind::StandardConstructor
        {
            let name = Self::standard_constructor_name(builtin)?;
            for key in Self::standard_constructor_candidate_keys(name) {
                if let Some((value, attributes)) =
                    self.standard_constructor_own_static(builtin, key)?
                {
                    let key = RuntimePropertyKey::String(JsString::from(key));
                    self.set_object_runtime_property(backing, key.clone(), value)?;
                    self.set_own_property_attributes(backing, &key, attributes)?;
                }
            }
            if Self::owns_species_getter(name) {
                self.define_species_getter(backing, name)?;
            }
        }
        Ok(Some(backing))
    }

    /// bd-9vouw.278: whether the constructor named `name` has its own
    /// `get [Symbol.species]` (the concrete typed array constructors inherit
    /// %TypedArray%'s).
    pub(super) fn owns_species_getter(name: &str) -> bool {
        prototype_getters::PROTOTYPE_GETTERS
            .iter()
            .any(|(owner, key, _)| *owner == name && *key == prototype_getters::SPECIES_GETTER_KEY)
    }

    /// bd-9vouw.278: the constructor `owner`'s `get [Symbol.species]` as an
    /// own accessor of `object`, its backing or property object: not
    /// enumerable, configurable, no setter.
    pub(super) fn define_species_getter(
        &mut self,
        object: ObjectId,
        owner: &str,
    ) -> Result<(), InterpreterError> {
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Species.id());
        self.define_accessor_property(
            object,
            key.clone(),
            Value::BuiltinFunction(BuiltinFunction::prototype_getter(
                owner,
                prototype_getters::SPECIES_GETTER_KEY,
            )),
            AccessorKind::Get,
        )?;
        self.set_own_property_attributes(
            object,
            &key,
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: true,
            },
        )
    }

    /// bd-9vouw.278: Get(C, @@species) for a built-in constructor `builtin`
    /// with no own-property object answering it, `receiver` being the
    /// constructor the lookup started at (a subclass reaching the built-in).
    /// Promise's getter lives on its property object; any other's on the
    /// backing object of its owner (`builtin`, or %TypedArray% for a
    /// concrete typed array constructor) from the moment that object exists.
    /// A present getter is called and a deleted one gives undefined; with no
    /// backing object yet, the getter's `return this` is the answer. `None`
    /// for a built-in without @@species.
    pub(super) fn builtin_species_value(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        receiver: Value,
    ) -> Result<Option<Value>, InterpreterError> {
        if !Self::builtin_has_default_species(builtin) {
            return Ok(None);
        }
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::Species.id());
        // `delete Promise[Symbol.species]` removes the getter from Promise's
        // property object; the read answered `return this` regardless.
        if let Some(properties) = Self::builtin_function_property_object(builtin) {
            return if self.chain_contains_runtime_property(properties, &key) {
                self.proxy_aware_get_runtime_property(Some(module), properties, &key, receiver, 0)
                    .map(Some)
            } else {
                Ok(Some(Value::Undefined))
            };
        }
        let owner = if builtin.kind == BuiltinFunctionKind::StandardConstructor
            && Self::standard_constructor_name(builtin)
                .is_ok_and(|name| TypedArrayKind::from_type_name(name).is_some())
        {
            Value::BuiltinFunction(BuiltinFunction::standard_constructor(TYPED_ARRAY_INTRINSIC))
        } else {
            Value::BuiltinFunction(builtin.clone())
        };
        match self.function_own_property_object(module, &owner)? {
            None => Ok(Some(receiver)),
            Some(object) if self.chain_contains_runtime_property(object, &key) => self
                .proxy_aware_get_runtime_property(Some(module), object, &key, receiver, 0)
                .map(Some),
            Some(_) => Ok(Some(Value::Undefined)),
        }
    }

    /// bd-9vouw.17: the own `name` or `length` a function has before its
    /// backing object exists; `None` for other keys and for a built-in whose
    /// `length` the engine does not model.
    pub(super) fn function_standard_own_value(
        &mut self,
        module: &Ir3Module,
        function: &Value,
        key: &str,
    ) -> Result<Option<Value>, InterpreterError> {
        if !matches!(key, "name" | "length") {
            return Ok(None);
        }
        Ok(match function {
            Value::Function(index) => Self::function_name_or_length(module, *index, key),
            Value::Closure(closure_id) => {
                Some(self.closure_property_value(module, *closure_id, key)?)
            }
            Value::GeneratorFunction(closure_id)
            | Value::AsyncFunction(closure_id)
            | Value::AsyncGeneratorFunction(closure_id) => {
                if let (Some(metadata), "name") =
                    (self.closure_method_metadata.get(closure_id), key)
                {
                    Some(Value::Str(metadata.name.clone()))
                } else {
                    let owner_module = self.foreign_closure_module(function, module)?;
                    let function_index = self.closure_function_index(*closure_id)?;
                    Self::function_name_or_length(
                        owner_module.as_deref().unwrap_or(module),
                        function_index,
                        key,
                    )
                }
            }
            Value::BuiltinFunction(builtin) => match builtin.kind {
                BuiltinFunctionKind::BoundFunction => self.bound_function_property(builtin, key)?,
                BuiltinFunctionKind::StandardConstructor => {
                    Some(self.standard_constructor_property(builtin, key)?)
                }
                // A `new Function` result is a handle to its compiled
                // artifact; its `length` is that descriptor's parameter count.
                BuiltinFunctionKind::GeneratedFunction if key == "length" => {
                    let (owner_program_id, artifact_id) =
                        Self::parse_generated_function_handle(builtin)?;
                    let artifact =
                        self.resolve_generated_function_artifact(owner_program_id, artifact_id)?;
                    Self::function_name_or_length(
                        &artifact.compiled_module,
                        artifact.function_index,
                        key,
                    )
                }
                _ if key == "name" => Some(Value::str(builtin.spec_name())),
                _ => builtin.spec_length().map(Value::Int),
            },
            _ => None,
        })
    }

    /// bd-9vouw.146: the TypeError of a strict-mode write to a read-only
    /// property (a function's `name` or `length`).
    pub(super) fn read_only_property_error(key: &RuntimePropertyKey) -> InterpreterError {
        InterpreterError::TypeError {
            expected: "writable property".to_string(),
            got: format!("read-only property {}", key.diagnostic()),
        }
    }

    /// Whether a function's backing object holds an own `key` (the program
    /// redefined it), without allocating a backing object. Runs no guest
    /// code.
    pub(super) fn function_backing_has_own_property(
        &self,
        module: &Ir3Module,
        function: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        Ok(self
            .function_own_property_object(module, function)?
            .and_then(|backing| self.heap.get(backing.0 as usize))
            .is_some_and(|object| object.contains_own_runtime_property(key)))
    }

    /// Whether `value` is a promise, generator, async generator or iterator
    /// object, whose own properties live on a backing object (see
    /// `function_own_property_key`).
    pub(super) fn has_exotic_backing_object(value: &Value) -> bool {
        matches!(
            value,
            Value::Promise(_)
                | Value::Generator(_)
                | Value::AsyncGeneratorObject(_)
                | Value::Iterator(_)
        )
    }

    /// Whether a promise, generator or async generator object has the own
    /// property `key` (on its backing object). Runs no guest code.
    pub(super) fn exotic_has_own_property(
        &self,
        module: &Ir3Module,
        value: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        Ok(self
            .function_own_property_object(module, value)?
            .and_then(|backing| self.heap.get(backing.0 as usize))
            .is_some_and(|object| object.contains_own_runtime_property(key)))
    }

    /// The own property `key` of a promise, generator or async generator
    /// object, read from its backing object with `value` as the receiver
    /// (an accessor sees it as `this`), with that backing object (the owner
    /// whose stored label the read joins), or `None` when it has none.
    pub(super) fn exotic_own_property_get(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<Option<(Value, ObjectId)>, InterpreterError> {
        if !self.exotic_has_own_property(module, value, key)? {
            return Ok(None);
        }
        let backing = self
            .function_own_property_object(module, value)?
            .expect("checked by exotic_has_own_property");
        let own =
            self.proxy_aware_get_runtime_property(Some(module), backing, key, value.clone(), 0)?;
        Ok(Some((own, backing)))
    }

    /// [[OwnPropertyKeys]] of a promise, generator, async generator or
    /// iterator object (bd-9vouw.149): its backing object's keys, or none
    /// when nothing was ever stored on it. Creates no backing object.
    pub(super) fn exotic_own_property_keys(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        let Some(backing) = self.own_property_holder(module, value, false)? else {
            return Ok(Vec::new());
        };
        self.join_pending_hostcall_stream_label(backing)?;
        self.proxy_aware_own_property_keys(module, backing, 0)
    }

    /// Whether `value` is an object whose own properties live on a backing
    /// object: a function (not a callable proxy, whose traps decide), a
    /// promise, a generator or an iterator.
    pub(super) fn stores_own_properties_on_backing(value: &Value) -> bool {
        (value.is_callable()
            && !matches!(value, Value::Object(_))
            && !Self::is_callable_proxy(value))
            || Self::has_exotic_backing_object(value)
    }

    /// The enumerable own String-keyed properties of a function, promise,
    /// generator or iterator, in property order, each read by [[Get]] with
    /// `value` as the receiver (Object.values / Object.entries, ES2020
    /// 7.3.23 EnumerableOwnPropertyNames). Creates no backing object.
    pub(super) fn backing_enumerable_own_entries(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
    ) -> Result<Vec<(JsString, Value)>, InterpreterError> {
        let Some(backing) = self.own_property_holder(module, value, false)? else {
            return Ok(Vec::new());
        };
        self.join_pending_hostcall_stream_label(backing)?;
        if self.active_proxy_record(backing)?.is_some() {
            return self.proxy_enumerable_own_entries(module, backing, value);
        }
        let keys = self
            .heap
            .get(backing.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: backing.0 })?
            .properties
            .exact_keys()
            .into_iter()
            .filter(|key| self.ordinary_own_string_key_is_enumerable(backing, key))
            .collect::<Vec<_>>();
        let mut entries = Vec::with_capacity(keys.len());
        for key in keys {
            let property_key = RuntimePropertyKey::String(key.clone());
            let property_value = self.proxy_aware_get_runtime_property(
                module,
                backing,
                &property_key,
                value.clone(),
                0,
            )?;
            entries.push((key, property_value));
        }
        Ok(entries)
    }

    /// bd-9vouw.17: the object that holds `value`'s own properties for the
    /// Object.* reflection built-ins: an object itself, a built-in's property
    /// object, or a function's backing object (created and seeded on demand
    /// when `create` is set). `None` for primitives, and for functions when
    /// no module is available or `create` is unset and nothing exists yet.
    pub(super) fn own_property_holder(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
        create: bool,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        if let Value::Object(id) = value {
            return Ok(Some(*id));
        }
        let holder = if let Value::BuiltinFunction(builtin) = value
            && let Some(object) = Self::builtin_function_property_object(builtin)
        {
            Some(object)
        } else {
            if !value.is_callable() && !Self::has_exotic_backing_object(value) {
                return Ok(None);
            }
            let Some(module) = module else {
                return Ok(None);
            };
            if create {
                self.ensure_function_own_property_object(module, value)?
            } else {
                self.function_own_property_object(module, value)?
            }
        };
        if create
            && let Some(backing) = holder
            && let Value::BuiltinFunction(builtin) = value
            && let Some(name) = Self::materialized_global_prototype_name(builtin)
        {
            // Proxy targets and integrity operations must see the same
            // intrinsic descriptor as direct reflection, including before
            // a constructor's backing object becomes non-extensible.
            self.ensure_materialized_prototype_property(backing, name)?;
        }
        if create
            && let (Some(module), Some(backing)) = (module, holder)
            && self.function_has_intrinsic_prototype(value)
            && !self
                .heap
                .get(backing.0 as usize)
                .is_some_and(|object| object.properties.contains_key("prototype"))
            && let Some(fields) = self.function_prototype_descriptor_fields(Some(module), value)?
        {
            // Install once through the existing descriptor machinery. Default
            // instance prototypes keep their separate class/constructor state.
            if !self.define_own_property_from_descriptor(
                backing,
                RuntimePropertyKey::String(JsString::from("prototype")),
                fields,
            )? {
                return Err(InterpreterError::InternalError {
                    details: "intrinsic function prototype could not be materialized".into(),
                });
            }
        }
        Ok(holder)
    }

    /// bd-9vouw.17: whether a function value has the own property `key`, or
    /// `None` if `function` is not a function this model covers. Once the
    /// backing object exists it decides (a deleted `name` is gone); before
    /// that the standard `name` and `length` are own. `prototype` keeps its
    /// dedicated rules in `object_own_property_contains`.
    pub(super) fn function_own_property_exists(
        &self,
        module: &Ir3Module,
        function: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<Option<bool>, InterpreterError> {
        let is_builtin_without_property_object = matches!(
            function,
            Value::BuiltinFunction(builtin)
                if Self::builtin_function_property_object(builtin).is_none()
        );
        if !matches!(
            function,
            Value::Function(_)
                | Value::Closure(_)
                | Value::GeneratorFunction(_)
                | Value::AsyncFunction(_)
                | Value::AsyncGeneratorFunction(_)
        ) && !is_builtin_without_property_object
        {
            return Ok(None);
        }
        if key.as_str() == Some("prototype") {
            return Ok(None);
        }
        if let Some(backing) = self.function_own_property_object(module, function)? {
            return Ok(Some(
                self.heap
                    .get(backing.0 as usize)
                    .is_some_and(|object| object.contains_own_runtime_property(key)),
            ));
        }
        Ok(Some(match (key.as_str(), function) {
            (Some("name"), _) => true,
            (Some("length"), Value::BuiltinFunction(builtin)) => {
                matches!(
                    builtin.kind,
                    BuiltinFunctionKind::BoundFunction
                        | BuiltinFunctionKind::StandardConstructor
                        | BuiltinFunctionKind::GeneratedFunction
                ) || builtin.spec_length().is_some()
            }
            (Some("length"), _) => true,
            _ => false,
        }))
    }

    pub(super) fn standard_constructor_name(
        builtin: &BuiltinFunction,
    ) -> Result<&'static str, InterpreterError> {
        STANDARD_CONSTRUCTOR_GLOBALS
            .iter()
            .copied()
            .chain([TYPED_ARRAY_INTRINSIC])
            .chain(FUNCTION_KIND_INTRINSICS)
            .find(|name| *name == &*builtin.module_specifier)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "standard constructor".to_string(),
                got: builtin.module_specifier.to_string(),
            })
    }

    /// bd-9vouw.17: the own property `key` of a first-class standard
    /// constructor other than `length` and `name`, with its attributes.
    /// `prototype` and the value properties (`Number.MAX_SAFE_INTEGER`,
    /// `Symbol.iterator`, `Uint8Array.BYTES_PER_ELEMENT`) are read-only, the
    /// static methods writable and configurable, all non-enumerable (ES2020
    /// clause 17); V8's `Error.stackTraceLimit` is a plain data property.
    /// `None` for a key the constructor only inherits (Function.prototype's
    /// members, %TypedArray%'s `from` and `of` on a concrete typed array
    /// constructor) and for one it does not have.
    pub(super) fn standard_constructor_own_static(
        &mut self,
        builtin: &BuiltinFunction,
        key: &str,
    ) -> Result<Option<(Value, PropertyAttributes)>, InterpreterError> {
        if matches!(key, "length" | "name") || Self::function_prototype_property(key).is_some() {
            return Ok(None);
        }
        let name = Self::standard_constructor_name(builtin)?;
        if matches!(key, "from" | "of") && TypedArrayKind::from_type_name(name).is_some() {
            return Ok(None);
        }
        let value = self.standard_constructor_property(builtin, key)?;
        if matches!(value, Value::Undefined) {
            return Ok(None);
        }
        let attributes = if key == "stackTraceLimit" {
            PropertyAttributes {
                writable: true,
                enumerable: true,
                configurable: true,
            }
        } else if key == "prototype" || !value.is_callable() {
            READ_ONLY_VALUE_ATTRIBUTES
        } else {
            NON_ENUMERABLE_DATA_ATTRIBUTES
        };
        Ok(Some((value, attributes)))
    }

    /// bd-9vouw.17: the keys a standard constructor's own properties can
    /// have besides `length` and `name`: `prototype`, the static methods Node
    /// has (BUILTIN_FUNCTION_LENGTHS), the Number constants, the well-known
    /// symbols, `BYTES_PER_ELEMENT` and `stackTraceLimit`.
    /// `standard_constructor_own_static` decides which ones it has.
    pub(super) fn standard_constructor_candidate_keys(name: &str) -> Vec<&'static str> {
        let mut keys = vec!["prototype"];
        keys.extend(
            builtin_function_lengths::BUILTIN_FUNCTION_LENGTHS
                .iter()
                .filter(|(owner, _, _)| *owner == name)
                .map(|(_, key, _)| *key),
        );
        match name {
            "Event" => keys.extend(
                event_target::EVENT_PHASE_CONSTANTS
                    .iter()
                    .map(|(constant, _)| *constant),
            ),
            "Number" => keys.extend([
                "EPSILON",
                "MAX_SAFE_INTEGER",
                "MAX_VALUE",
                "MIN_SAFE_INTEGER",
                "MIN_VALUE",
                "NaN",
                "NEGATIVE_INFINITY",
                "POSITIVE_INFINITY",
            ]),
            "Symbol" => {
                keys.extend(
                    crate::object_model::WellKnownSymbol::ALL
                        .into_iter()
                        .filter_map(|symbol| symbol.name().strip_prefix("@@")),
                );
                keys.extend(["dispose", "asyncDispose"]);
            }
            "Error" => keys.push("stackTraceLimit"),
            _ if TypedArrayKind::from_type_name(name).is_some() => keys.push("BYTES_PER_ELEMENT"),
            _ => {}
        }
        keys
    }

    /// A materialized standard constructor owns its initial statics and all
    /// later writes. Deleted members continue on its actual [[Prototype]]
    /// instead of being synthesized again (bd-9vouw.366). RegExp's legacy
    /// statics retain their dynamic match-state path; they are not seeded
    /// on the ordinary property backing.
    pub(super) fn authoritative_standard_constructor_backing(
        &self,
        module: &Ir3Module,
        function: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let Value::BuiltinFunction(builtin) = function else {
            return Ok(None);
        };
        if builtin.kind != BuiltinFunctionKind::StandardConstructor
            || (&*builtin.module_specifier == "RegExp"
                && key.as_str().is_some_and(is_legacy_regexp_static))
        {
            return Ok(None);
        }
        self.function_own_property_object(module, function)
    }

    /// bd-9vouw.17: members of a first-class standard constructor value.
    pub(super) fn standard_constructor_property(
        &mut self,
        builtin: &BuiltinFunction,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        let name = Self::standard_constructor_name(builtin)?;
        Ok(match key {
            // ES2020 26.2.2: the Proxy constructor has no `prototype`.
            "prototype" if name == "Proxy" => Value::Undefined,
            "prototype" => Value::Object(self.ensure_builtin_prototype(name)?),
            "name" => Value::str(name),
            "length" => Value::Int(match name {
                "Map"
                | "Set"
                | "WeakMap"
                | "WeakSet"
                | "Symbol"
                | "URLSearchParams"
                | "EventTarget"
                | "AbortController"
                | "AbortSignal"
                | "DOMException"
                | "Blob"
                | "Iterator"
                | TYPED_ARRAY_INTRINSIC => 0,
                "RegExp" | "AggregateError" | "Proxy" => 2,
                "Buffer" => 3,
                name if TypedArrayKind::from_type_name(name).is_some() => 3,
                _ => 1,
            }),
            "poolSize" if name == "Buffer" => Value::Int(8192),
            "from" if name == "Iterator" => iterator_helpers::helper_method("Iterator.from"),
            key if name == "AbortSignal" && Self::abort_signal_static(key).is_some() => {
                Self::abort_signal_static(key).expect("guarded above")
            }
            key if name == "Event" => event_target::EVENT_PHASE_CONSTANTS
                .iter()
                .find(|(constant, _)| *constant == key)
                .map_or(Value::Undefined, |(_, value)| Value::Int(*value)),
            "canParse" | "parse" if name == "URL" => Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::UrlStatic,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(key),
                iterator_handle: None,
                bound_object: None,
            }),
            "asUintN" if name == "BigInt" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::BigIntAsUintN,
            )),
            // V8 statics that Node code relies on: Error.captureStackTrace
            // and Error.stackTraceLimit (10, as in V8).
            "captureStackTrace" if name == "Error" => Value::BuiltinFunction(
                BuiltinFunction::new_kind(BuiltinFunctionKind::ErrorCaptureStackTrace),
            ),
            "stackTraceLimit" if name == "Error" => Value::Int(10),
            // bd-9vouw.113: RegExp.$1, lastMatch, ... from the last match.
            key if name == "RegExp" && is_legacy_regexp_static(key) => {
                self.legacy_regexp_static_value(key)?
            }
            "asIntN" if name == "BigInt" => {
                Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::BigIntAsIntN))
            }
            // The pinned Node 22 surface uses registered symbols, unlike
            // later ECMAScript well-known disposal symbols. Reuse the charged,
            // replayed registry without changing the thirteen ES2020 IDs.
            "dispose" if name == "Symbol" => {
                Value::Symbol(self.intern_global_symbol(JsString::from("nodejs.dispose"))?)
            }
            "asyncDispose" if name == "Symbol" => {
                Value::Symbol(self.intern_global_symbol(JsString::from("nodejs.asyncDispose"))?)
            }
            // Symbol.iterator, Symbol.toStringTag, ... (ES2020 19.4.2).
            key if name == "Symbol"
                && crate::object_model::WellKnownSymbol::from_property_name(key).is_some() =>
            {
                let symbol = crate::object_model::WellKnownSymbol::from_property_name(key)
                    .expect("guarded above");
                Value::Symbol(symbol.id())
            }
            "BYTES_PER_ELEMENT" if TypedArrayKind::from_type_name(name).is_some() => {
                let kind = TypedArrayKind::from_type_name(name).expect("guarded above");
                Value::Int(i64::try_from(kind.element_size()).unwrap_or(i64::MAX))
            }
            // Inherited from %TypedArray% (ES2020 22.2.2).
            method @ ("from" | "of")
                if name == TYPED_ARRAY_INTRINSIC
                    || TypedArrayKind::from_type_name(name).is_some() =>
            {
                Value::BuiltinFunction(BuiltinFunction::typed_array_static(method))
            }
            _ => {
                if let Some(value) = Self::function_prototype_property(key) {
                    value
                } else if let Some(tag) =
                    crate::lowering_pipeline::slot0_static_member_capability(name, key)
                {
                    Value::BuiltinFunction(BuiltinFunction::static_hostcall(tag))
                } else if name == "Object"
                    && let Some(tag) =
                        crate::lowering_pipeline::object_receiver_static_member_capability(key)
                {
                    // `const eq = Object.is` (mobx's default comparer):
                    // these read as values too; a value call passes its
                    // arguments without the receiver placeholder their
                    // call-site convention adds (call_static_hostcall).
                    Value::BuiltinFunction(BuiltinFunction::static_hostcall(tag))
                } else if name == "Number" {
                    Self::number_constructor_constant(key).unwrap_or(Value::Undefined)
                } else {
                    Value::Undefined
                }
            }
        })
    }

    pub(super) fn number_constructor_constant(key: &str) -> Option<Value> {
        Some(match key {
            "MAX_SAFE_INTEGER" => Value::Int(MAX_SAFE_INTEGER),
            "MIN_SAFE_INTEGER" => Value::Int(MIN_SAFE_INTEGER),
            "EPSILON" => Value::Float(Float64::new(f64::EPSILON)),
            "MAX_VALUE" => Value::Float(Float64::new(f64::MAX)),
            "MIN_VALUE" => Value::Float(Float64::new(f64::from_bits(1))),
            "POSITIVE_INFINITY" => Value::Float(Float64::new(f64::INFINITY)),
            "NEGATIVE_INFINITY" => Value::Float(Float64::new(f64::NEG_INFINITY)),
            "NaN" => Value::Float(Float64::new(f64::NAN)),
            _ => return None,
        })
    }

    /// bd-9vouw.17: `[[Call]]` / `[[Construct]]` of a first-class standard
    /// constructor. Each name routes to the implementation its direct call
    /// already uses; `new` and plain calls share one path, as for every
    /// builtin constructor here (so `new Number(1)` yields the primitive, the
    /// same documented gap as `builtin:String`: boxed primitives are deferred).
    /// ArrayBuffer, DataView and the concrete typed array constructors,
    /// which construct through their `builtin:` hostcalls and throw when
    /// called without `new`.
    pub(super) fn buffer_family_constructor(name: &str) -> bool {
        matches!(name, "ArrayBuffer" | "DataView") || TypedArrayKind::from_type_name(name).is_some()
    }

    pub(super) fn call_standard_constructor(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let name = Self::standard_constructor_name(builtin)?;
        match name {
            "Error" | "TypeError" | "RangeError" | "ReferenceError" | "SyntaxError"
            | "EvalError" | "URIError" => self.construct_error_object(Some(module), name, args),
            "AggregateError" => self.construct_aggregate_error(Some(module), args),
            "Number" => self.dispatch_builtin_hostcall("builtin:Number", args, Some(module)),
            "String" => self.dispatch_builtin_hostcall("builtin:String", args, Some(module)),
            "Boolean" => self.dispatch_builtin_hostcall("builtin:Boolean", args, Some(module)),
            // ES2020 23.1.1.1, 23.2.1.1, 23.3.1.1, 23.4.1.1: called rather
            // than constructed (NewTarget undefined), the collection
            // constructors throw; construction reaches builtin:Map and the
            // like (and initialize_builtin_subclass_instance), never this
            // call path. `Map()` returned a map.
            "Map" | "Set" | "WeakMap" | "WeakSet" => {
                Err(self.throw_js_error("TypeError", format!("Constructor {name} requires 'new'")))
            }
            // ES2020 26.2.1.1: Proxy called without `new` throws; the
            // Construct arm builds proxies. So do WeakRef and
            // FinalizationRegistry (ES2021 26.1.1.1, 26.2.1.1).
            "Proxy" => Err(InterpreterError::TypeError {
                expected: "new Proxy(target, handler)".to_string(),
                got: "Proxy called without new".to_string(),
            }),
            "WeakRef" | "FinalizationRegistry" | "SharedArrayBuffer" => {
                Err(InterpreterError::TypeError {
                    expected: format!("new {name}(...)"),
                    got: format!("Constructor {name} requires 'new'"),
                })
            }
            "Iterator" => Err(self.throw_js_error(
                "TypeError",
                "Constructor Iterator requires 'new'".to_string(),
            )),
            name if event_target::EVENT_TARGET_FAMILY.contains(&name) || name == "Blob" => {
                Err(InterpreterError::TypeError {
                    expected: format!("new {name}(...)"),
                    got: format!("Class constructor {name} cannot be invoked without 'new'"),
                })
            }
            "Symbol" => self.dispatch_builtin_hostcall("builtin:Symbol", args, Some(module)),
            // `RegExp(p, f)` called; a construction through a RegExp value
            // (`new R(p, f)`, Reflect.construct) dispatches from
            // construct_builtin_with_new_target.
            "RegExp" => {
                let pattern_value = self.arg_or_undefined(args, 0)?;
                let flags_value = self.arg_or_undefined(args, 1)?;
                self.construct_regexp(Some(module), pattern_value, flags_value, true)
            }
            "TextEncoder" => self.construct_text_encoder(),
            "TextDecoder" => self.construct_text_decoder(Some(module), args),
            "URL" => self.dispatch_builtin_hostcall("builtin:Url", args, Some(module)),
            "URLSearchParams" => {
                self.dispatch_builtin_hostcall("builtin:UrlSearchParams", args, Some(module))
            }
            // The deprecated Buffer(arg) / new Buffer(arg): a size allocates
            // a zero-filled buffer, anything else is Buffer.from(arg, ...).
            "Buffer" => {
                let tag = if matches!(
                    self.builtin_arg(args, 0)?,
                    Some(Value::Int(_) | Value::Float(_))
                ) {
                    "builtin:BufferAlloc"
                } else {
                    "builtin:BufferFrom"
                };
                self.dispatch_builtin_hostcall(tag, args, Some(module))
            }
            // ES2024 25.1.4.1, 25.3.2.1, 23.2.5.1: called rather than
            // constructed (NewTarget undefined), ArrayBuffer, DataView and
            // the typed array constructors throw; `new` and Reflect.construct
            // reach their construction directly (bd-9vouw.273).
            name if Self::buffer_family_constructor(name) => Err(InterpreterError::TypeError {
                expected: format!("new {name}(...)"),
                got: format!("Constructor {name} requires 'new'"),
            }),
            // ES2020 22.2.1.1: %TypedArray% only serves as a superclass.
            TYPED_ARRAY_INTRINSIC => Err(InterpreterError::TypeError {
                expected: "a concrete typed array constructor".to_string(),
                got: "Abstract class TypedArray not directly constructable".to_string(),
            }),
            // A generator or async function from source text, through the
            // Function constructor's contained-codegen path (bd-9vouw.321).
            name if FUNCTION_KIND_INTRINSICS.contains(&name) => {
                let kind = DynamicFunctionKind::for_constructor(name).ok_or_else(|| {
                    InterpreterError::InternalError {
                        details: format!("{name} has no dynamic function kind"),
                    }
                })?;
                self.construct_dynamic_function(module, args, kind)
            }
            "Array" => {
                let values = self.call_arguments(args)?;
                if let [length @ (Value::Int(_) | Value::Float(_))] = values.as_slice() {
                    // `Array(n)`: an empty array whose length is n (holes),
                    // through the ordinary length-assignment semantics
                    // (RangeError for a non-uint32 length).
                    let length = length.clone();
                    let array = self.alloc_array_from_values(&[])?;
                    self.set_object_property(array, "length".to_string(), length)?;
                    Ok(Value::Object(array))
                } else {
                    Ok(Value::Object(self.alloc_array_from_values(&values)?))
                }
            }
            "Object" => {
                let value = self.call_arguments(args)?.into_iter().next();
                match value {
                    None | Some(Value::Undefined | Value::Null) => {
                        Ok(Value::Object(self.alloc_object_with_prototype(None)?))
                    }
                    Some(value) if value.is_object_like() => Ok(value),
                    // ES2020 19.1.1.1 step 3: ToObject(value).
                    Some(value) => Ok(Value::Object(self.alloc_primitive_wrapper(value)?)),
                }
            }
            "BigInt" => {
                // ES2020 20.2.1.1 step 2: ToPrimitive(value, number) first,
                // so an object's valueOf / toString / @@toPrimitive decides
                // (it was a TypeError for every object).
                let value = self
                    .call_arguments(args)?
                    .into_iter()
                    .next()
                    .unwrap_or(Value::Undefined);
                let value = if value.is_object_like() {
                    self.coerce_runtime_primitive(Some(module), value, false)?
                } else {
                    value
                };
                self.bigint_from_value(value)
            }
            _ => Err(InterpreterError::TypeError {
                expected: "callable standard constructor".to_string(),
                got: name.to_string(),
            }),
        }
    }

    /// Throw a genuine JS error of class `name` (a canonical builtin error
    /// constructor) carrying `message`, catchable by guest `try`/`catch`.
    pub(super) fn throw_js_error(
        &mut self,
        name: &'static str,
        message: String,
    ) -> InterpreterError {
        let thrown = (|| {
            let prototype = self.ensure_builtin_prototype(name)?;
            let error_id = self.alloc_object_with_prototype(Some(prototype))?;
            self.initialize_error_like_object(error_id, name, message)?;
            Ok::<Value, InterpreterError>(Value::Object(error_id))
        })();
        let thrown = match thrown {
            Ok(value) => value,
            Err(error) => return error,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    /// `BigInt(value)` for the primitive inputs the engine represents.
    /// ToBigInt (ES2020 7.1.13): Numbers are a TypeError, unlike `BigInt()`.
    pub(super) fn coerce_to_bigint(&mut self, value: Value) -> Result<Value, InterpreterError> {
        match value {
            Value::Int(_) | Value::Float(_) | Value::Undefined | Value::Null | Value::Symbol(_) => {
                Err(InterpreterError::TypeError {
                    expected: "value convertible to BigInt".to_string(),
                    got: value.type_name().to_string(),
                })
            }
            other => self.bigint_from_value(other),
        }
    }

    pub(super) fn bigint_from_value(&mut self, value: Value) -> Result<Value, InterpreterError> {
        let digits = match value {
            Value::BigInt(digits) => return Ok(Value::BigInt(digits)),
            Value::Int(n) => n.to_string(),
            Value::Bool(b) => i64::from(b).to_string(),
            Value::Float(f) if f.inner().is_finite() && f.inner().fract() == 0.0 => {
                format!("{:.0}", f.inner())
            }
            Value::Float(f) => {
                return Err(self.throw_js_error(
                    "RangeError",
                    format!(
                        "The number {f} cannot be converted to a BigInt because it is not an integer"
                    ),
                ));
            }
            Value::Str(s) => {
                let text = s.to_string();
                match bigint_ops::from_string(&text) {
                    Some(digits) => digits,
                    None => {
                        return Err(self.throw_js_error(
                            "SyntaxError",
                            format!("Cannot convert {text} to a BigInt"),
                        ));
                    }
                }
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "value convertible to BigInt".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        Ok(Value::BigInt(Arc::from(digits.as_str())))
    }

    /// bd-9vouw.17: call a first-class static builtin. The tag is
    /// re-validated against the shared lowering tables and passes the same
    /// hostcall capability gate as a direct call, so a value can never reach
    /// a hostcall that direct-call interception would not.
    pub(super) fn call_static_hostcall(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let tag: &str = &builtin.module_specifier;
        if static_hostcall_name(tag).is_none() {
            return Err(InterpreterError::TypeError {
                expected: "known static builtin".to_string(),
                got: tag.to_string(),
            });
        }
        // Preserve the existing deterministic rejection of a nonpositive
        // randomInt range when the same method is called through a value.
        // This selects a validation-only hostcall that cannot draw entropy;
        // all valid or otherwise unresolved calls retain RandomRead authority.
        let invalid_random_range = tag == "builtin:CryptoRandomInt"
            && match args.count {
                1 => matches!(self.builtin_arg(args, 0)?, Some(Value::Int(max)) if max <= 0),
                2 => matches!(
                    (self.builtin_arg(args, 0)?, self.builtin_arg(args, 1)?),
                    (Some(Value::Int(min)), Some(Value::Int(max))) if min >= max
                ),
                _ => false,
            };
        let tag = if invalid_random_range {
            "builtin:CryptoInvalidRandomInt"
        } else {
            tag
        }
        .to_string();
        let instruction_index = u32::try_from(self.ip).unwrap_or(u32::MAX);
        check_hostcall_capability_gate(self, &tag, instruction_index)?;
        if let Some(value) = self.object_receiver_static_value_call(module, &tag, args)? {
            return Ok(value);
        }
        // The value call of a static builtin is its hostcall, which counts
        // itself as a builtin: counted twice, the dispatch looked nested in
        // another builtin's frame and could not arm a collection, so since
        // call-time member resolution (2a427674d) `Reflect.construct(C, a)`
        // ran a constructor allocating past the object cap without one
        // (bd-9vouw.77). This frame holds only the tag and the argument
        // registers across the call.
        self.gc_exit_builtin();
        let result = self.dispatch_builtin_hostcall(&tag, args, Some(module));
        self.gc_enter_builtin();
        result
    }

    /// A value call of `Object.is`, `isExtensible`, `preventExtensions`,
    /// `seal` or `isSealed` (`const eq = Object.is; eq(a, b)`). Their hostcall
    /// handlers read past a receiver slot the call-site convention adds, and
    /// a value call's arguments have none, so these run here over the
    /// arguments as passed. `None` for any other tag.
    pub(super) fn object_receiver_static_value_call(
        &mut self,
        module: &Ir3Module,
        tag: &str,
        args: RegRange,
    ) -> Result<Option<Value>, InterpreterError> {
        let arg = |core: &Self, index: u32| -> Result<Value, InterpreterError> {
            Ok(core.builtin_arg(args, index)?.unwrap_or(Value::Undefined))
        };
        Ok(Some(match tag {
            "builtin:ObjectIs" => Value::Bool(Self::same_value(&arg(self, 0)?, &arg(self, 1)?)),
            "builtin:ObjectIsExtensible" => self.object_integrity_builtin(
                Some(module),
                args,
                ObjectIntegrityOperation::IsExtensible,
                false,
            )?,
            "builtin:ObjectPreventExtensions" => self.object_integrity_builtin(
                Some(module),
                args,
                ObjectIntegrityOperation::PreventExtensions,
                false,
            )?,
            "builtin:ObjectSeal" => self.object_seal_value(Some(module), arg(self, 0)?)?,
            "builtin:ObjectIsSealed" => {
                let object = arg(self, 0)?;
                Value::Bool(self.object_is_sealed_value(Some(module), &object)?)
            }
            _ => return Ok(None),
        }))
    }

    /// Whether `object_id`'s prototype chain passes through a canonical
    /// builtin error prototype (`Error` or one of the six native errors).
    /// Whether `object_id` is a RegExp or inherits from %RegExp.prototype%,
    /// so the RegExp.prototype methods reach it.
    pub(super) fn chain_has_regexp_prototype(&self, object_id: ObjectId) -> bool {
        self.regexp_source_flags_from_object(object_id).is_some()
            || self.chain_reaches_canonical_prototype(object_id, "RegExp")
    }

    /// Whether `object_id` is, or inherits from, the canonical prototype of
    /// the builtin `name` (which exists only once something has used it).
    pub(super) fn chain_reaches_canonical_prototype(
        &self,
        object_id: ObjectId,
        name: &str,
    ) -> bool {
        let Some(&prototype) = self.builtin_prototypes.get(name) else {
            return false;
        };
        let mut current = Some(object_id);
        let mut depth = 0u32;
        while let Some(id) = current {
            if id == prototype {
                return true;
            }
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return false;
            }
            current = self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.prototype);
            depth += 1;
        }
        false
    }

    pub(super) fn chain_has_error_prototype(&self, object_id: ObjectId) -> bool {
        const ERROR_PROTOTYPES: [&str; 8] = [
            "Error",
            "TypeError",
            "RangeError",
            "ReferenceError",
            "SyntaxError",
            "EvalError",
            "URIError",
            "AggregateError",
        ];
        let mut current = Some(object_id);
        let mut depth = 0u32;
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return false;
            }
            if self.builtin_prototypes.iter().any(|(name, prototype)| {
                *prototype == id && ERROR_PROTOTYPES.contains(&name.as_str())
            }) {
                return true;
            }
            current = self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.prototype);
            depth += 1;
        }
        false
    }

    /// ES2020 20.5.3.4 Error.prototype.toString.
    pub(super) fn error_prototype_to_string(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: "object receiver for Error.prototype.toString".to_string(),
                got: receiver.type_name().to_string(),
            });
        };
        let name =
            self.proxy_aware_get_property(Some(module), object_id, "name", receiver.clone(), 0)?;
        let message =
            self.proxy_aware_get_property(Some(module), object_id, "message", receiver.clone(), 0)?;
        // Steps 4 and 6: ToString, so a Symbol name or message is a
        // TypeError and a throwing conversion hook propagates.
        let name = match name {
            Value::Undefined => "Error".to_string(),
            other => self
                .scoped_conversion(|this| this.conversion_to_string(Some(module), other))?
                .to_string(),
        };
        let message = match message {
            Value::Undefined => String::new(),
            other => self
                .scoped_conversion(|this| this.conversion_to_string(Some(module), other))?
                .to_string(),
        };
        let text = if name.is_empty() {
            message
        } else if message.is_empty() {
            name
        } else {
            format!("{name}: {message}")
        };
        self.check_string_limit(text.len())?;
        Ok(Value::str(text))
    }

    /// The builtin method `key` that the canonical prototype registered as
    /// `name` in `builtin_prototypes` supplies virtually (bd-9vouw.17): these
    /// prototypes do not store their methods as own heap properties.
    pub(super) fn canonical_prototype_method(name: &str, key: &str) -> Option<Value> {
        let defined = |value: Value| (!matches!(value, Value::Undefined)).then_some(value);
        match name {
            "EventTarget" | "Event" | "AbortController" | "AbortSignal" => {
                Self::event_target_prototype_method(name, key)
            }
            // %Array.prototype% is itself an Array whose length is 0
            // (ES2020 22.1.3), bd-9vouw.122.
            "Array" if key == "length" => Some(Value::Int(0)),
            "Array" => Self::array_prototype_method(key).map(Value::BuiltinFunction),
            "String" => Self::string_prototype_method(key),
            "Number" => defined(Self::number_property_value(key)),
            "Boolean" => Self::boolean_prototype_method(key),
            "BigInt" => defined(Self::bigint_property_value(key)),
            "Symbol" => match key {
                "toString" => Some(Value::BuiltinFunction(BuiltinFunction::symbol_to_string())),
                "valueOf" => Some(Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::SymbolPrototypeValueOf,
                ))),
                _ => None,
            },
            // %Function.prototype% is itself a function with length 0 and
            // the empty name (ES2020 19.2.3), bd-9vouw.17.
            "Function" if key == "length" => Some(Value::Int(0)),
            "Function" if key == "name" => Some(Value::str("")),
            "Function"
                if matches!(
                    key,
                    "hasOwnProperty" | "propertyIsEnumerable" | "isPrototypeOf"
                ) =>
            {
                None
            }
            "Function" => Self::function_prototype_property(key),
            "Promise" => defined(Self::promise_property_value(key)),
            // DataView: the accessors instances already expose, served from
            // the canonical prototype too.
            "Map"
            | "Set"
            | "Date"
            | "RegExp"
            | "WeakMap"
            | "WeakSet"
            | "DataView"
            | "ArrayBuffer"
            | "SharedArrayBuffer"
            | "WeakRef"
            | "FinalizationRegistry"
            | "TextEncoder"
            | "TextDecoder"
            | "URLSearchParams" => {
                Self::collection_prototype_method(name, key).map(Value::BuiltinFunction)
            }
            // The shared typed array methods are element-type agnostic.
            "TypedArray" => {
                Self::typed_array_prototype_method("Int8Array", key).map(Value::BuiltinFunction)
            }
            // Buffer.prototype's own methods (toString, slice, read*, ...)
            // shadow %TypedArray.prototype%'s; the rest are inherited
            // (bd-9vouw.104). The chain lookup stops at the first canonical
            // prototype, so this answers for both.
            "Buffer" => Self::buffer_prototype_method(key)
                .map(Value::BuiltinFunction)
                .or_else(|| Self::canonical_prototype_method("TypedArray", key)),
            // The rest of a URL's members are answered by the instance.
            "URL" if matches!(key, "toString" | "toJSON") => {
                Some(Value::BuiltinFunction(BuiltinFunction {
                    kind: BuiltinFunctionKind::UrlMethod,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(key),
                    iterator_handle: None,
                    bound_object: None,
                }))
            }
            "Blob" => BuiltinFunction::blob_method(key).map(Value::BuiltinFunction),
            _ => None,
        }
    }

    /// bd-9vouw.17: a builtin method named `key` on the first canonical
    /// prototype in `object_id`'s chain that supplies methods virtually.
    pub(super) fn builtin_prototype_method_for_chain(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Option<Value> {
        if VIRTUAL_METHOD_PROTOTYPES
            .iter()
            .all(|name| Self::canonical_prototype_method(name, key).is_none())
        {
            return None;
        }
        let mut current = Some(object_id);
        let mut depth = 0u32;
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return None;
            }
            let name = self
                .builtin_prototypes
                .iter()
                .find(|(_, prototype)| **prototype == id)
                .map(|(name, _)| name.as_str());
            // A method `delete` removed from this prototype (bd-9vouw.93)
            // is looked up further along the chain.
            // A prototype without the method passes the lookup on to its own
            // [[Prototype]], as [[Get]] does: AbortSignal.prototype holds
            // throwIfAborted, EventTarget.prototype addEventListener
            // (bd-9vouw.170).
            if let Some(name) = name
                && VIRTUAL_METHOD_PROTOTYPES.contains(&name)
                && !(self.virtual_property_deletions
                    && self.virtual_own_property_deleted(
                        id,
                        &RuntimePropertyKey::String(JsString::from(key)),
                    ))
                && let Some(method) = Self::canonical_prototype_method(name, key)
            {
                return Some(method);
            }
            current = self.observable_prototype_of(id);
            depth += 1;
        }
        None
    }

    /// A builtin that the canonical prototype `object_id` itself (not an
    /// object inheriting from it) supplies virtually, which ES2020 17 makes
    /// an own data property { writable: true, enumerable: false,
    /// configurable: true }: its methods and its `constructor`. This keeps
    /// `Array.prototype.hasOwnProperty('map')` and
    /// `Object.getOwnPropertyDescriptor(Date.prototype, 'getTime')` in step
    /// with [[Get]]. Real own properties are checked first by the callers.
    pub(super) fn canonical_prototype_own_virtual_value(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Option<Value> {
        let name = self
            .builtin_prototypes
            .iter()
            .find(|(_, prototype)| **prototype == object_id)
            .map(|(name, _)| name.as_str())?;
        if self.virtual_property_deletions
            && self.virtual_own_property_deleted(
                object_id,
                &RuntimePropertyKey::String(JsString::from(key)),
            )
        {
            return None;
        }
        if key == "constructor" && matches!(name, "Promise" | "Date") {
            return self.materialized_intrinsic_constructor(name);
        }
        // %Function.prototype%.constructor is %Function% (ES2020 19.2.3.1).
        if key == "constructor" && name == "Function" {
            return Some(Value::BuiltinFunction(
                BuiltinFunction::function_constructor(),
            ));
        }
        if key == "constructor" && name == TYPED_ARRAY_INTRINSIC {
            return Some(Value::BuiltinFunction(
                BuiltinFunction::standard_constructor(TYPED_ARRAY_INTRINSIC),
            ));
        }
        if key == "constructor" {
            return STANDARD_CONSTRUCTOR_GLOBALS
                .iter()
                .copied()
                .chain(FUNCTION_KIND_INTRINSICS)
                .find(|candidate| *candidate == name)
                .map(|name| Value::BuiltinFunction(BuiltinFunction::standard_constructor(name)));
        }
        match name {
            "Object" => Self::object_prototype_method(key).map(Value::BuiltinFunction),
            "Error" if key == "toString" => Some(Value::BuiltinFunction(
                BuiltinFunction::new_kind(BuiltinFunctionKind::ErrorPrototypeToString),
            )),
            // Function.prototype inherits these from Object.prototype.
            "Function"
                if matches!(
                    key,
                    "hasOwnProperty" | "propertyIsEnumerable" | "isPrototypeOf"
                ) =>
            {
                None
            }
            _ if VIRTUAL_METHOD_PROTOTYPES.contains(&name) => {
                Self::canonical_prototype_method(name, key)
            }
            _ => None,
        }
    }

    /// bd-9vouw.93: whether `delete` removed `key`, a virtual own property of
    /// the canonical prototype `object_id`.
    pub(super) fn virtual_own_property_deleted(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> bool {
        self.virtual_property_deletions
            && self
                .heap
                .get(object_id.0 as usize)
                .is_some_and(|object| object.deleted_virtual_keys.contains(key))
    }

    /// [`Self::virtual_own_property_deleted`] on the canonical prototype
    /// named `name`, when that prototype exists (an unallocated one cannot
    /// have lost anything).
    pub(super) fn canonical_virtual_property_deleted(
        &self,
        name: &str,
        key: &RuntimePropertyKey,
    ) -> bool {
        self.virtual_property_deletions
            && self
                .builtin_prototypes
                .get(name)
                .is_some_and(|object_id| self.virtual_own_property_deleted(*object_id, key))
    }

    /// [`Self::canonical_virtual_property_deleted`] for a String key.
    pub(super) fn canonical_virtual_name_deleted(&self, name: &str, key: &str) -> bool {
        self.virtual_property_deletions
            && self.canonical_virtual_property_deleted(
                name,
                &RuntimePropertyKey::String(JsString::from(key)),
            )
    }

    /// The virtual own property `key` of the canonical prototype `object_id`
    /// unless `delete` removed it: a String-keyed method, `constructor` or
    /// `length` ([`Self::canonical_prototype_own_virtual_value`]), or one of
    /// the Symbol-keyed methods the prototype supplies (@@iterator of Array,
    /// %TypedArray%, Map, Set, String and URLSearchParams; RegExp's
    /// @@match/@@replace/@@search/@@split/@@matchAll). Its attributes are
    /// { writable: true, enumerable: false, configurable: true }, except
    /// %Array.prototype%.length (non-configurable).
    pub(super) fn canonical_prototype_virtual_property(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<Value> {
        let symbol = match key {
            RuntimePropertyKey::String(name) => {
                return self.canonical_prototype_own_virtual_value(object_id, name.as_str()?);
            }
            RuntimePropertyKey::Symbol(symbol) => *symbol,
        };
        let name = self
            .builtin_prototypes
            .iter()
            .find(|(_, prototype)| **prototype == object_id)
            .map(|(name, _)| name.as_str())?;
        if self.virtual_own_property_deleted(object_id, key) {
            return None;
        }
        if symbol == WellKnownSymbol::Iterator.id() {
            let builtin = match name {
                "Array" => BuiltinFunction::array_values(),
                "TypedArray" => BuiltinFunction::typed_array_values(),
                "Map" => BuiltinFunction::new_kind(BuiltinFunctionKind::MapEntries),
                "Set" => BuiltinFunction::new_kind(BuiltinFunctionKind::SetValues),
                "String" => BuiltinFunction::new_kind(BuiltinFunctionKind::StringIterator),
                "URLSearchParams" => {
                    BuiltinFunction::new_kind(BuiltinFunctionKind::UrlSearchParamsEntries)
                }
                _ => return None,
            };
            return Some(Value::BuiltinFunction(builtin));
        }
        (name == "RegExp")
            .then(|| regexp_symbol_method_key(symbol))
            .flatten()
            .map(|method| Value::BuiltinFunction(BuiltinFunction::regexp_symbol_method(method)))
    }

    /// Whether the virtual own property `key` of the canonical prototype
    /// `object_id` is configurable: all are but %Array.prototype%.length
    /// (ES2020 22.1.3, an Array's `length`).
    /// Whether a write may replace the virtual own property `key` of the
    /// canonical prototype `object_id`: every one is writable except
    /// %Function.prototype%'s `length` and `name` (ES2020 19.2.3), while they
    /// have not been deleted.
    pub(super) fn virtual_property_is_writable(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> bool {
        !(matches!(key.as_str(), Some("length" | "name"))
            && self.builtin_prototypes.get("Function") == Some(&object_id)
            && self
                .canonical_prototype_virtual_property(object_id, key)
                .is_some())
    }

    pub(super) fn virtual_property_is_configurable(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> bool {
        !(key.as_str() == Some("length")
            && self.builtin_prototypes.get("Array") == Some(&object_id))
    }

    /// The attributes of the virtual own data property `key` of the
    /// canonical prototype `object_id`: %Function.prototype%'s `length` and
    /// `name` are read-only, %Array.prototype%.length is non-configurable,
    /// and the rest are { writable: true, enumerable: false, configurable:
    /// true }.
    pub(super) fn virtual_property_attributes(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> PropertyAttributes {
        if matches!(key.as_str(), Some("length" | "name"))
            && self.builtin_prototypes.get("Function") == Some(&object_id)
        {
            FUNCTION_NAME_LENGTH_ATTRIBUTES
        } else if self.virtual_property_is_configurable(object_id, key) {
            NON_ENUMERABLE_DATA_ATTRIBUTES
        } else {
            PropertyAttributes {
                writable: true,
                enumerable: false,
                configurable: false,
            }
        }
    }

    /// bd-9vouw.379: store the virtual own property `key` of the canonical
    /// prototype `object_id` (a method, `constructor`, @@iterator, or a
    /// getter-only accessor such as `Map.prototype.size`) as an ordinary own
    /// property with its attributes, so [[DefineOwnProperty]] validates
    /// against them and keeps the fields a descriptor leaves out, and a
    /// [[Set]] replaces only its value. Both took the property as absent:
    /// `Object.defineProperty(Array.prototype, 'map', { value })` left `map`
    /// non-writable and non-configurable, and `Array.prototype.forEach =
    /// Array.prototype.forEach` made it enumerable, so for-in over every
    /// array listed it. The stored property shadows the virtual one and
    /// `delete` removes both. Answers whether a property was stored.
    pub(super) fn materialize_virtual_own_property(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        if self.heap.get(object_id.0 as usize).is_none_or(|object| {
            object.contains_own_runtime_property(key)
                || (object.is_array && key.as_str() == Some("length"))
        }) || !self
            .builtin_prototypes
            .values()
            .any(|prototype| *prototype == object_id)
        {
            return Ok(false);
        }
        let (value, attributes) =
            if let Some(value) = self.canonical_prototype_virtual_property(object_id, key) {
                (value, self.virtual_property_attributes(object_id, key))
            } else if let Some(getter) = self.prototype_getter_at(object_id, key) {
                let setter = key.as_str().and_then(|name| {
                    self.builtin_prototypes
                        .iter()
                        .find(|(_, prototype)| **prototype == object_id)
                        .and_then(|(owner, _)| Self::prototype_accessor_setter(owner, name))
                });
                (
                    Self::accessor_property_value(Some(Value::BuiltinFunction(getter)), setter),
                    NON_ENUMERABLE_DATA_ATTRIBUTES,
                )
            } else {
                return Ok(false);
            };
        self.set_object_runtime_property(object_id, key.clone(), value)?;
        self.set_own_property_attributes(object_id, key, attributes)?;
        Ok(true)
    }

    /// `delete` of the virtual own property `key` of a canonical prototype
    /// (bd-9vouw.93): recorded so the virtual lookups skip it.
    pub(super) fn delete_virtual_own_property(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        let index = object_id.0 as usize;
        if self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .deleted_virtual_keys
            .contains(key)
        {
            return Ok(());
        }
        self.apply_memory_component_delta(0, Self::estimate_property_attributes_entry_bytes(key))?;
        self.mutate_heap(|heap| heap[index].deleted_virtual_keys.insert(key.clone()));
        self.virtual_property_deletions = true;
        Ok(())
    }

    /// bd-9vouw.17: virtual, non-enumerable `constructor` of the canonical
    /// builtin prototypes (and of arrays, which carry no prototype object).
    pub(super) fn standard_constructor_for_chain(&self, object_id: ObjectId) -> Option<Value> {
        let constructor = |name: &'static str| {
            Value::BuiltinFunction(BuiltinFunction::standard_constructor(name))
        };
        // A `constructor` deleted from a canonical prototype (bd-9vouw.93)
        // is skipped: the walk goes on to the next prototype.
        let constructor_key = RuntimePropertyKey::String(JsString::from("constructor"));
        if (self.heap.get(object_id.0 as usize)?.is_array
            || self.chain_inherits_array_prototype(object_id))
            && !self.canonical_virtual_property_deleted("Array", &constructor_key)
        {
            return Some(constructor("Array"));
        }
        let mut current = Some(object_id);
        let mut depth = 0u32;
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                break;
            }
            let canonical = self
                .builtin_prototypes
                .iter()
                .find(|(_, prototype)| **prototype == id)
                .map(|(name, _)| name.as_str())
                .filter(|_| !self.virtual_own_property_deleted(id, &constructor_key));
            // %Promise.prototype%.constructor is %Promise% and
            // %Date.prototype%.constructor is %Date%, materialized
            // constructors rather than standard constructor builtins.
            if let Some(name @ ("Promise" | "Date")) = canonical {
                return self.materialized_intrinsic_constructor(name);
            }
            if canonical == Some("Function") {
                return Some(Value::BuiltinFunction(
                    BuiltinFunction::function_constructor(),
                ));
            }
            if canonical == Some(TYPED_ARRAY_INTRINSIC) {
                return Some(constructor(TYPED_ARRAY_INTRINSIC));
            }
            if let Some(name) = canonical.and_then(|name| {
                STANDARD_CONSTRUCTOR_GLOBALS
                    .iter()
                    .copied()
                    .chain(FUNCTION_KIND_INTRINSICS)
                    .find(|candidate| *candidate == name)
            }) {
                return Some(constructor(name));
            }
            current = self.observable_prototype_of(id);
            depth += 1;
        }
        // Every other ordinary chain ends at %Object.prototype%, whose
        // `constructor` is `Object` (bd-9vouw.34).
        (self.chain_reaches_object_prototype(object_id)
            && !self.canonical_virtual_property_deleted("Object", &constructor_key))
        .then(|| constructor("Object"))
    }

    /// Write register `val` to `property_key` on ordinary backing storage,
    /// preserving the original receiver for inherited setters and Proxy traps.
    /// The caller admits the receiver/key/value mutation label before entering;
    /// stage the own value label here and restore it if no own write commits.
    pub(super) fn set_backing_object_property(
        &mut self,
        module: &Ir3Module,
        property_object: ObjectId,
        property_key: &RuntimePropertyKey,
        val: u32,
        receiver: Value,
        strict: bool,
    ) -> Result<(), InterpreterError> {
        self.run_pre_runtime_property_access_hook(module, property_object, property_key)?;
        let set_val = self.read_reg(val)?;
        let value_label = self.get_register_label(val)?.clone();
        let previous_label = self.own_stored_runtime_property_label(property_object, property_key);
        self.set_own_runtime_property_label(property_object, property_key, &value_label)?;
        let set_result = self.proxy_aware_set_runtime_property(
            Some(module),
            property_object,
            property_key,
            set_val,
            receiver,
            0,
        );
        let committed = match set_result {
            Ok(committed) => committed,
            Err(error) => {
                self.set_own_runtime_property_label(
                    property_object,
                    property_key,
                    &previous_label,
                )?;
                return Err(error);
            }
        };
        if !committed {
            self.set_own_runtime_property_label(property_object, property_key, &previous_label)?;
            // bd-9vouw.146: a sloppy write that [[Set]] rejects is ignored.
            if !strict {
                return Ok(());
            }
            return Err(InterpreterError::TypeError {
                expected: "successful builtin property write".to_string(),
                got: "falsy set result".to_string(),
            });
        }
        if !self.heap[property_object.0 as usize].contains_own_runtime_property(property_key) {
            self.set_own_runtime_property_label(property_object, property_key, &previous_label)?;
        }
        Ok(())
    }

    /// Resolve the function index backing a closure handle, erroring if the
    /// closure table no longer holds it.
    pub(super) fn closure_function_index(&self, closure_id: u32) -> Result<u32, InterpreterError> {
        self.closures
            .get(closure_id as usize)
            .map(|c| c.function_index)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid closure".to_string(),
                got: format!("closure#{closure_id} not found"),
            })
    }

    // -- JSON.parse lexical helpers (bd-9a8cz.4, bd-ktt99) ----------------
    // The iterative container machine lives in json_parse::document. Tokens
    // operate on exact UTF-16 code units so raw lone surrogates never pass
    // through a lossy UTF-8 projection (bd-4v2up).

    pub(super) fn json_skip_ws(units: &[u16], pos: &mut usize) {
        while matches!(units.get(*pos), Some(0x20 | 0x09 | 0x0A | 0x0D)) {
            *pos += 1;
        }
    }

    /// Parse a JSON string token directly over exact UTF-16 code units. Both
    /// raw units and `\uXXXX` escapes remain exact: paired surrogates heal into
    /// one scalar, while a lone surrogate remains representable in [`JsString`].
    pub(super) fn json_parse_string(units: &[u16], pos: &mut usize) -> Option<JsString> {
        if units.get(*pos) != Some(&0x22) {
            return None;
        }
        *pos += 1;
        let mut parsed = Vec::new();
        while let Some(&unit) = units.get(*pos) {
            *pos += 1;
            match unit {
                0x22 => return Some(JsString::from_code_units(&parsed)),
                0x5C => {
                    let &escaped = units.get(*pos)?;
                    *pos += 1;
                    match escaped {
                        0x22 => parsed.push(0x22),
                        0x5C => parsed.push(0x5C),
                        0x2F => parsed.push(0x2F),
                        0x62 => parsed.push(0x08),
                        0x66 => parsed.push(0x0C),
                        0x6E => parsed.push(0x0A),
                        0x72 => parsed.push(0x0D),
                        0x74 => parsed.push(0x09),
                        0x75 => {
                            if *pos + 4 > units.len() {
                                return None;
                            }
                            let mut code = 0u16;
                            for &digit in &units[*pos..*pos + 4] {
                                let nibble = match digit {
                                    0x30..=0x39 => digit - 0x30,
                                    0x41..=0x46 => digit - 0x41 + 10,
                                    0x61..=0x66 => digit - 0x61 + 10,
                                    _ => return None,
                                };
                                code = (code << 4) | nibble;
                            }
                            *pos += 4;
                            parsed.push(code);
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1F => return None,
                _ => parsed.push(unit),
            }
        }
        None
    }

    /// Parse a JSON number token into an Int (when integral) or Float.
    pub(super) fn json_parse_number(units: &[u16], pos: &mut usize) -> Option<Value> {
        let start = *pos;
        if units.get(*pos) == Some(&0x2D) {
            *pos += 1;
        }
        match units.get(*pos) {
            Some(0x30) => {
                *pos += 1;
                if matches!(units.get(*pos), Some(0x30..=0x39)) {
                    return None;
                }
            }
            Some(0x31..=0x39) => {
                *pos += 1;
                while matches!(units.get(*pos), Some(0x30..=0x39)) {
                    *pos += 1;
                }
            }
            _ => return None,
        }
        let mut is_float = false;
        if units.get(*pos) == Some(&0x2E) {
            is_float = true;
            *pos += 1;
            let fraction_start = *pos;
            while matches!(units.get(*pos), Some(0x30..=0x39)) {
                *pos += 1;
            }
            if *pos == fraction_start {
                return None;
            }
        }
        if matches!(units.get(*pos), Some(0x65 | 0x45)) {
            is_float = true;
            *pos += 1;
            if matches!(units.get(*pos), Some(0x2B | 0x2D)) {
                *pos += 1;
            }
            let exponent_start = *pos;
            while matches!(units.get(*pos), Some(0x30..=0x39)) {
                *pos += 1;
            }
            if *pos == exponent_start {
                return None;
            }
        }
        let token = String::from_utf16(&units[start..*pos]).ok()?;
        if token == "-0" {
            return Some(Value::Float(Float64::new(-0.0)));
        }
        if !is_float
            && let Ok(value) = token.parse::<i64>()
            && (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&value)
        {
            return Some(Value::Int(value));
        }
        token
            .parse::<f64>()
            .ok()
            .map(|value| Value::Float(Float64::new(value)))
    }

    pub(super) fn json_finalize_array_len(
        &mut self,
        id: ObjectId,
        len: u32,
    ) -> Result<(), InterpreterError> {
        self.json_store_parsed_property(id, JsString::from("length"), Value::Int(i64::from(len)))?;
        let idx = id.0 as usize;
        self.mutate_heap(|heap| {
            if let Some(obj) = heap.get_mut(idx) {
                obj.cached_dense_length = Some(len);
            }
        });
        Ok(())
    }

    pub(super) fn rollback_json_parse(&mut self, heap_len: usize, estimated_memory_bytes: u64) {
        self.rollback_heap_to_len(heap_len);
        self.estimated_memory_bytes = estimated_memory_bytes;
    }

    /// Get the number of objects on the heap.
    pub fn heap_size(&self) -> usize {
        self.heap.len()
    }

    /// Return the current live-memory estimate used by the interpreter.
    pub fn estimated_memory_bytes(&self) -> u64 {
        self.total_memory_bytes_from_base(self.estimated_memory_bytes)
    }

    // -- Witness emission --------------------------------------------------

    /// Commit to callback order, exact callable identity, and its
    /// position among retained witness events. Typed serialization includes
    /// builtin bindings/module identity that Display omits. Streaming into
    /// SHA-256 keeps both retained and temporary storage constant-sized; a
    /// closure/function is its handle, not a traversal of its captured graph.
    pub(super) fn callback_witness_step(
        &self,
        callback: &Value,
        previous: Option<(u64, ContentHash)>,
        domain: &[u8],
    ) -> Result<(u64, ContentHash), InterpreterError> {
        struct HashWriter<'a>(&'a mut Sha256);

        impl Write for HashWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                Digest::update(self.0, bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (count, previous) = previous.unwrap_or((0, ContentHash::default()));
        let count = count
            .checked_add(1)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "callback witness count overflow".to_string(),
            })?;
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(previous.as_bytes());
        hasher.update(count.to_be_bytes());
        hasher.update(self.witness_seq.to_be_bytes());
        hasher.update((self.ip as u64).to_be_bytes());
        hasher.update(self.instructions_executed.to_be_bytes());
        serde_json::to_writer(HashWriter(&mut hasher), callback).map_err(|error| {
            InterpreterError::InternalError {
                details: format!("callback witness serialization failed: {error}"),
            }
        })?;
        Ok((count, ContentHash::from_bytes(hasher.finalize().into())))
    }

    pub(super) fn record_timer_callback_witness(
        &mut self,
        callback: &Value,
    ) -> Result<(), InterpreterError> {
        self.timer_callback_witness = Some(self.callback_witness_step(
            callback,
            self.timer_callback_witness,
            b"franken-engine.timer-callback-chain.v1\0",
        )?);
        Ok(())
    }

    /// The existing timer completion marker carries one domain-separated
    /// aggregate instead of a row for every callback. The IR4 seal and strict
    /// re-execution bind this payload just like every retained witness event.
    /// Taking it here also prevents a successful reused core from carrying a
    /// previous execution's callbacks into its next result.
    pub(super) fn seal_timer_callback_witness(&mut self) {
        if let Some((count, digest)) = self.timer_callback_witness.take() {
            self.emit_witness(
                WitnessEventKind::ExecutionCompleted,
                Some(&format!("timer_callbacks_v1:{count}:{}", digest.to_hex())),
            );
        }
    }

    /// Preserve every successful enqueue's identity and order without keeping
    /// a grant/dispatch pair for every microtask. Strict replay recomputes this
    /// domain-separated payload through the same IR4 sealing path as timers.
    pub(super) fn seal_microtask_enqueue_witness(&mut self) {
        if let Some((count, digest)) = self.microtask_enqueue_witness.take() {
            self.emit_witness(
                WitnessEventKind::ExecutionCompleted,
                Some(&format!(
                    "microtask_enqueues_v1:{count}:{}",
                    digest.to_hex()
                )),
            );
        }
    }

    pub(super) fn emit_witness(&mut self, kind: WitnessEventKind, detail: Option<&str>) {
        self.flush_sandbox_witness();
        let payload = detail.unwrap_or("").as_bytes();
        self.witness_events.push(WitnessEvent {
            seq: self.witness_seq,
            kind,
            instruction_index: self.ip as u32,
            payload_hash: ContentHash::compute(payload),
            timestamp_tick: self.instructions_executed,
        });
        self.witness_seq += 1;
    }

    /// Build a deterministic [`SecurityEventContext`] for a runtime security
    /// observability record emitted from the live execution path. The
    /// timestamp is the deterministic instruction tick (not wall-clock) so the
    /// resulting structured log replays byte-identically.
    pub(super) fn capability_denial_event_context(
        &self,
        instruction_index: u32,
    ) -> SecurityEventContext {
        SecurityEventContext {
            timestamp_ns: self.instructions_executed,
            trace_id: self.trace_id.clone(),
            principal_id: String::new(),
            decision_id: format!("instr-{instruction_index}"),
            policy_id: String::new(),
            zone_id: String::new(),
            component: COMPONENT.to_string(),
        }
    }

    /// Mandatory runtime security metrics accumulated during this execution
    /// (e.g. `capability_denial_total`), fed from the real runtime failure
    /// sites. See [`RuntimeSecurityObservability`].
    pub fn security_metrics(&self) -> &RuntimeSecurityMetrics {
        self.security_observability.metrics()
    }

    /// The full runtime security observability surface (metrics + structured
    /// security log) populated by this interpreter on the live execution path.
    pub fn security_observability(&self) -> &RuntimeSecurityObservability {
        &self.security_observability
    }

    /// Live hostcall telemetry recorder driven from each `dispatch_*_hostcall`
    /// path (bd-qi3hs). Pass this recorder to
    /// [`crate::forensic_replayer::IncidentTrace::with_telemetry_recorder`] so
    /// replay receives both retained records and completeness evidence.
    /// Drop counts cover instrumented dispatch sites; they are not a substitute
    /// for keeping every policy-relevant dispatch family wired to the recorder.
    /// Capability denials occur before dispatch and are retained in the
    /// execution result's `hostcall_decisions`, not this post-dispatch stream.
    pub fn hostcall_telemetry(&self) -> &TelemetryRecorder {
        &self.telemetry_recorder
    }

    /// Best-effort recording for a single completed hostcall. Capability
    /// denials occur before this point and are recorded by the shared gate in
    /// `HostcallDecisionRecord`. Backpressure and other recorder errors are
    /// swallowed so telemetry can never block JS execution; the recorder is
    /// observability, not enforcement.
    pub(super) fn record_hostcall_telemetry(
        &mut self,
        cap: &str,
        args: crate::ir_contract::RegRange,
        timestamp_ns: u64,
        arguments_hash: ContentHash,
        outcome: &Result<Value, InterpreterError>,
    ) {
        let result_status = match outcome {
            Ok(_) => TelemetryHostcallResult::Success,
            Err(err) => TelemetryHostcallResult::Error {
                code: interpreter_error_telemetry_code(err),
            },
        };
        let extension_id = if self.trace_id.is_empty() {
            "anonymous-execution".to_string()
        } else {
            self.trace_id.clone()
        };
        let capability_used = RuntimeCapability::from_tag_str(cap)
            // Internal-only tags (`promise:*`, `ifc.check_flow`) have no real
            // capability gate. We surface them under `VmDispatch`, the umbrella
            // capability every JS execution already requires, so the schema
            // field stays meaningful instead of being silently dropped.
            .unwrap_or(RuntimeCapability::VmDispatch);
        // bd-f1w0r: replace the previously-hardcoded
        // `FlowLabel::new("public", "public")` with the real label dimension
        // surfaced by bd-n2mjy (HostCall now joins arg labels onto dst).
        // label_class = join over the input registers' IFC labels — falls
        // back to Public if the join walks off the register file (which
        // would also be the previous hardcoded value, so no regression).
        // clearance_class = "internal" — the engine's baseline operating
        // clearance, an honest default that beats the prior "public" since
        // the capability gate has already approved this hostcall by the
        // time we get here. Wiring a per-capability clearance (e.g. from
        // the gate's HostcallCapabilityClass) is tracked separately.
        let args_label = self
            .join_arg_range_label(args)
            .unwrap_or(crate::ifc_artifacts::Label::Public);
        let input = RecordInput {
            extension_id,
            hostcall_type: TelemetryHostcallType::from_capability_tag(cap),
            capability_used,
            arguments_hash,
            result_status,
            // The deterministic timestamp source is the interpreter's
            // instruction counter (not wall-clock), so wall-time duration is
            // intentionally zero — every replay produces byte-identical
            // records.
            duration_ns: 0,
            resource_delta: ResourceDelta::default(),
            flow_label: FlowLabel::new(args_label.to_string(), "internal"),
            decision_id: None,
        };
        // Recorder errors are intentionally swallowed: telemetry must never
        // block JS execution. The recorder is observability, not enforcement.
        let _ = self.telemetry_recorder.record(timestamp_ns, input);
    }

    /// Hash the argument register values that an in-flight hostcall is about to
    /// consume, so the recorder schema's `arguments_hash` reflects the real
    /// inputs without persisting the (potentially sensitive) raw values.
    /// Failure modes (register out-of-bounds, etc.) collapse to a
    /// schema-stable "unreadable args" sentinel so telemetry can never break
    /// the hot path.
    pub(super) fn hostcall_arguments_hash(&self, args: RegRange) -> ContentHash {
        let mut buf: Vec<u8> = Vec::with_capacity((args.count as usize).saturating_mul(32));
        buf.extend_from_slice(b"hostcall-args/v1\n");
        buf.extend_from_slice(&args.count.to_le_bytes());
        for i in 0..args.count {
            let Some(reg) = args.start.checked_add(i) else {
                return ContentHash::compute(b"hostcall-args/unreadable");
            };
            let reg_index = self.register_base + reg as usize;
            let Some(value) = self.registers.value.get(reg_index) else {
                return ContentHash::compute(b"hostcall-args/unreadable");
            };
            match serde_json::to_vec(value) {
                Ok(bytes) => {
                    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                    buf.extend_from_slice(&bytes);
                }
                Err(_) => return ContentHash::compute(b"hostcall-args/unreadable"),
            }
        }
        ContentHash::compute(&buf)
    }

    // -- Structured events -------------------------------------------------

    pub(super) fn push_event(&mut self, event: &str, outcome: &str, err_code: Option<&str>) {
        self.push_component_event(COMPONENT, event, outcome, err_code);
    }

    pub(super) fn push_component_event(
        &mut self,
        component: &str,
        event: &str,
        outcome: &str,
        err_code: Option<&str>,
    ) {
        let event = InterpreterEvent {
            trace_id: self.trace_id.clone(),
            component: component.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: err_code.map(str::to_string),
        };
        // bd-zaeeh: general structured events are charged against the
        // containment budget and dropped deterministically at the exact
        // ceiling rather than accumulating unbounded (a core reused across
        // repeated failing executions retains its event vector). Dropping
        // keeps this diagnostic surface from ever pushing the estimate past
        // `max_total_memory_bytes`; the drop is recorded as evidence.
        let event_bytes = Self::estimate_interpreter_event_bytes(&event);
        if self.memory_request_exceeds_budget(
            self.estimated_memory_bytes.saturating_add(event_bytes),
            self.config.max_total_memory_bytes,
        ) {
            self.dropped_event_count = self.dropped_event_count.saturating_add(1);
            return;
        }
        self.events.push(event);
        self.general_event_bytes = self.general_event_bytes.saturating_add(event_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(event_bytes);
    }
}
