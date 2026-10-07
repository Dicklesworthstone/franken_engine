//! ES2020 24.4 Atomics for a single agent (bd-9vouw.245).
//!
//! `Atomics` was not defined: about 125 Node-passing Test262 tests failed
//! with "Atomics is not defined", and code that sleeps with
//! `Atomics.wait(int32, 0, 0, ms)` (atomic-sleep, under pino's sonic-boom)
//! fell back to busy-waiting.
//!
//! One agent runs, so every operation is a plain read-modify-write of the
//! element, through the typed array element encoders, which wrap a value as
//! a store does. `wait` on a shared Int32Array or BigInt64Array answers
//! "not-equal" when the element differs. Otherwise nothing can notify it:
//! a finite timeout advances the deterministic clock by that many
//! milliseconds and answers "timed-out" (Node blocks that long), and an
//! infinite one is refused with a TypeError instead of waiting forever.
//! `notify` finds no waiters and answers 0.
//!
//! No-claim: `Atomics.waitAsync` is not provided.

use super::*;

/// The members of the `Atomics` namespace (Node v22.2.0 also has
/// `waitAsync`).
pub(super) const ATOMICS_METHODS: [&str; 12] = [
    "load",
    "store",
    "add",
    "sub",
    "and",
    "or",
    "xor",
    "exchange",
    "compareExchange",
    "isLockFree",
    "wait",
    "notify",
];

impl BuiltinFunction {
    /// The `Atomics` member `name`.
    pub(super) fn atomics_method(name: &str) -> Option<Self> {
        ATOMICS_METHODS.contains(&name).then(|| Self {
            kind: BuiltinFunctionKind::AtomicsMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(name),
            iterator_handle: None,
            bound_object: None,
        })
    }
}

impl InterpreterCore {
    /// The `Atomics` namespace object: non-enumerable methods and an
    /// @@toStringTag of "Atomics" (writable false, configurable true).
    pub(super) fn alloc_atomics_global(&mut self) -> Result<ObjectId, InterpreterError> {
        let members: Vec<(&str, Value)> = ATOMICS_METHODS
            .iter()
            .filter_map(|name| {
                BuiltinFunction::atomics_method(name)
                    .map(|method| (*name, Value::BuiltinFunction(method)))
            })
            .collect();
        let atomics = self.alloc_object_with_properties(&members)?;
        self.mark_builtin_members_non_enumerable(atomics)?;
        let tag = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
        self.set_object_runtime_property(atomics, tag.clone(), Value::str("Atomics"))?;
        self.set_own_property_attributes(
            atomics,
            &tag,
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: true,
            },
        )?;
        Ok(atomics)
    }

    /// An `Atomics` method call.
    pub(super) fn atomics_method_call(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let method = builtin
            .module_specifier
            .0
            .as_deref()
            .unwrap_or_default()
            .to_string();
        if method == "isLockFree" {
            // V8 reports 1, 2, 4 and 8 byte accesses as lock-free.
            let size = self.atomics_integer_arg(module, args, 0)?;
            return Ok(Value::Bool(matches!(size, 1.0 | 2.0 | 4.0 | 8.0)));
        }
        let waitable = matches!(method.as_str(), "wait" | "notify");
        let (view, shared) = self.atomics_typed_array(args, waitable)?;
        if method == "wait" && !shared {
            return Err(InterpreterError::TypeError {
                expected: "a shared typed array for Atomics.wait".to_string(),
                got: format!(
                    "[object {}] is not a shared typed array.",
                    view.kind.type_name()
                ),
            });
        }
        let index = self.atomics_index(module, args, &view)?;
        let result = self.atomics_operation(module, &method, args, &view, index)?;
        // IFC, after any guest conversion code has run: a write joins every
        // argument's label into the bytes, and an answer read from (or
        // compared against) the element carries the bytes' label, as the
        // typed array element paths do.
        if !matches!(method.as_str(), "load" | "wait" | "notify") {
            let written = self.join_arg_range_label(args)?;
            self.join_binary_storage_label(view.buffer, &written)?;
        }
        if method != "notify" {
            let storage = self.binary_storage_label(view.buffer);
            let pending = self
                .pending_hostcall_result_label
                .clone()
                .unwrap_or(Label::Public)
                .join(&storage);
            self.replace_pending_hostcall_result_label(Some(pending))?;
        }
        Ok(result)
    }

    /// The operation `method` on element `index` of `view`.
    fn atomics_operation(
        &mut self,
        module: &Ir3Module,
        method: &str,
        args: RegRange,
        view: &TypedArrayView,
        index: usize,
    ) -> Result<Value, InterpreterError> {
        match method {
            "load" => self.atomics_read(&view, index),
            "store" => {
                let value = self.atomics_value_arg(module, args, 2, view.kind)?;
                self.atomics_write(&view, index, &value)?;
                Ok(value)
            }
            "add" | "sub" | "and" | "or" | "xor" | "exchange" => {
                let value = self.atomics_value_arg(module, args, 2, view.kind)?;
                let operand = Self::atomics_bits(view.kind, &value)?;
                let old = self.atomics_read(&view, index)?;
                let old_bits = Self::atomics_bits(view.kind, &old)?;
                let new_bits = match method {
                    "add" => old_bits.wrapping_add(operand),
                    "sub" => old_bits.wrapping_sub(operand),
                    "and" => old_bits & operand,
                    "or" => old_bits | operand,
                    "xor" => old_bits ^ operand,
                    _ => operand,
                };
                self.atomics_write_bits(&view, index, new_bits)?;
                Ok(old)
            }
            "compareExchange" => {
                let expected = self.atomics_value_arg(module, args, 2, view.kind)?;
                let replacement = self.atomics_value_arg(module, args, 3, view.kind)?;
                let old = self.atomics_read(&view, index)?;
                if Self::atomics_bits(view.kind, &old)? == Self::atomics_bits(view.kind, &expected)?
                {
                    self.atomics_write(&view, index, &replacement)?;
                }
                Ok(old)
            }
            "wait" => {
                let expected = self.atomics_value_arg(module, args, 2, view.kind)?;
                let timeout = match self.builtin_number_arg(module, args, 3)? {
                    None | Some(Value::Undefined) => f64::INFINITY,
                    Some(value) => Self::coerce_to_float(&value).unwrap_or(f64::NAN),
                };
                let timeout = if timeout.is_nan() {
                    f64::INFINITY
                } else {
                    timeout.max(0.0)
                };
                let current = self.atomics_read(&view, index)?;
                if Self::atomics_bits(view.kind, &current)?
                    != Self::atomics_bits(view.kind, &expected)?
                {
                    return Ok(Value::str("not-equal"));
                }
                if timeout.is_infinite() {
                    return Err(InterpreterError::TypeError {
                        expected: "a finite timeout for Atomics.wait".to_string(),
                        got: "a wait no other agent can end".to_string(),
                    });
                }
                // Fold the guest's own work into the clock, then let the
                // timeout pass on it.
                self.virtual_wall_clock_ms();
                let now = self.event_loop.clock.now_ms();
                self.event_loop
                    .clock
                    .advance_to(now.saturating_add(timeout.ceil() as u64));
                Ok(Value::str("timed-out"))
            }
            "notify" => {
                // ES2020 24.4.12 step 3: the count converts (undefined is
                // +Infinity) even though no agent waits.
                if !matches!(self.builtin_arg(args, 2)?, None | Some(Value::Undefined)) {
                    self.atomics_integer_arg(module, args, 2)?;
                }
                Ok(Value::Int(0))
            }
            _ => Err(InterpreterError::TypeError {
                expected: "an Atomics method".to_string(),
                got: method.to_string(),
            }),
        }
    }

    /// ValidateIntegerTypedArray (ES2020 24.4.1.1): an integer typed array
    /// other than Uint8ClampedArray, or with `waitable` an Int32Array or
    /// BigInt64Array; also whether its buffer is a SharedArrayBuffer.
    fn atomics_typed_array(
        &self,
        args: RegRange,
        waitable: bool,
    ) -> Result<(TypedArrayView, bool), InterpreterError> {
        let target = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let view = match &target {
            Value::Object(id) => self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.typed_array.clone()),
            _ => None,
        };
        let Some(view) = view else {
            return Err(InterpreterError::TypeError {
                expected: "an integer typed array for Atomics".to_string(),
                got: target.type_name().to_string(),
            });
        };
        // ValidateTypedArray: out of bounds is a TypeError (bd-9vouw.256).
        Self::reject_out_of_bounds_typed_array(&view, "Atomics")?;
        let allowed = if waitable {
            matches!(view.kind, TypedArrayKind::Int32 | TypedArrayKind::BigInt64)
        } else {
            !matches!(
                view.kind,
                TypedArrayKind::Float32 | TypedArrayKind::Float64 | TypedArrayKind::Uint8Clamped
            )
        };
        if !allowed {
            return Err(InterpreterError::TypeError {
                expected: "an integer typed array for Atomics".to_string(),
                got: format!(
                    "[object {}] is not an integer typed array.",
                    view.kind.type_name()
                ),
            });
        }
        let shared = self
            .heap
            .get(view.buffer.0 as usize)
            .is_some_and(|buffer| buffer.brand() == Some("SharedArrayBuffer"));
        Ok((view, shared))
    }

    /// ValidateAtomicAccess (ES2020 24.4.1.2): ToIndex of the index, which
    /// must be below the array's length (a RangeError otherwise).
    fn atomics_index(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        view: &TypedArrayView,
    ) -> Result<usize, InterpreterError> {
        let raw = self
            .builtin_number_arg(module, args, 1)?
            .unwrap_or(Value::Undefined);
        let invalid = || InterpreterError::RangeError {
            message: "Invalid atomic access index".to_string(),
        };
        let index = Self::to_index_value(&raw)?.ok_or_else(invalid)?;
        usize::try_from(index)
            .ok()
            .filter(|index| *index < view.length)
            .ok_or_else(invalid)
    }

    /// The value argument at `index`: ToBigInt for a BigInt array, else
    /// ToIntegerOrInfinity as a Number (-0 is +0).
    fn atomics_value_arg(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        index: u32,
        kind: TypedArrayKind,
    ) -> Result<Value, InterpreterError> {
        if kind.is_bigint() {
            let value = self.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
            let primitive = self.object_to_number_primitive(Some(module), value)?;
            return self.typed_array_prepare_value(kind, primitive);
        }
        let integer = self.atomics_integer_arg(module, args, index)?;
        Ok(js_number_to_value(integer))
    }

    /// ToIntegerOrInfinity of the argument at `index` (NaN and undefined
    /// are 0, -0 is +0).
    fn atomics_integer_arg(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        index: u32,
    ) -> Result<f64, InterpreterError> {
        let value = self
            .builtin_number_arg(module, args, index)?
            .unwrap_or(Value::Undefined);
        let number = Self::coerce_to_float(&value).unwrap_or(f64::NAN);
        Ok(if number.is_nan() {
            0.0
        } else {
            number.trunc() + 0.0
        })
    }

    /// The element at `index`, as a typed array read gives it.
    fn atomics_read(&self, view: &TypedArrayView, index: usize) -> Result<Value, InterpreterError> {
        self.with_array_buffer_bytes(view.buffer, |bytes| {
            Self::read_typed_array_element_bytes(view, bytes, index)
        })?
    }

    /// Store `value` at `index` as a typed array write does.
    fn atomics_write(
        &mut self,
        view: &TypedArrayView,
        index: usize,
        value: &Value,
    ) -> Result<(), InterpreterError> {
        let (kind, offset) = (view.kind, view.byte_offset);
        self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
            Self::write_typed_array_element_bytes_at_offset(kind, offset, bytes, index, value)
        })?
    }

    /// The element's raw bits for `value` (how a store would encode it), as
    /// an unsigned integer of the element's width.
    fn atomics_bits(kind: TypedArrayKind, value: &Value) -> Result<u64, InterpreterError> {
        let mut slot = [0u8; 8];
        Self::write_typed_array_element_bytes(kind, &mut slot, 0, value)?;
        Ok(u64::from_le_bytes(slot) & Self::atomics_width_mask(kind))
    }

    /// Store raw element bits (the low bits of `bits`) at `index`.
    fn atomics_write_bits(
        &mut self,
        view: &TypedArrayView,
        index: usize,
        bits: u64,
    ) -> Result<(), InterpreterError> {
        let size = view.kind.element_size();
        let (start, end) = Self::typed_array_element_range(view.kind, view.byte_offset, index)?;
        let encoded = (bits & Self::atomics_width_mask(view.kind)).to_le_bytes();
        self.with_array_buffer_bytes_mut(view.buffer, |bytes| match bytes.get_mut(start..end) {
            Some(slot) => {
                slot.copy_from_slice(&encoded[..size]);
                Ok(())
            }
            None => Err(InterpreterError::RangeError {
                message: "Invalid atomic access index".to_string(),
            }),
        })?
    }

    fn atomics_width_mask(kind: TypedArrayKind) -> u64 {
        match kind.element_size() {
            8 => u64::MAX,
            size => (1u64 << (size * 8)) - 1,
        }
    }
}
