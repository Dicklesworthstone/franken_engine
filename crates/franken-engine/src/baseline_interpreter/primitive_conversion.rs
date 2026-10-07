//! Observable global conversions and numeric parsers (ECMAScript 2020).
//!
//! Conversion hooks run on the VM, in specification order, before parsing.
//! Integer prefixes accumulate exactly in bounded limbs and round once to
//! binary64; neither i64 saturation nor per-digit floating rounding is valid.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum PrimitiveConversion {
    Number,
    String,
    Boolean,
    IsNaN,
    IsFinite,
    ParseInt,
    ParseFloat,
    PropertyKey,
}

impl InterpreterCore {
    /// bd-9vouw.117: a builtin's numeric argument (a position, a count, a
    /// radix, digits) after ToPrimitive with hint "number": an object's
    /// @@toPrimitive, valueOf or toString runs, as ToNumber requires (ES2020
    /// 7.1.4), and a Symbol or BigInt is a TypeError. A primitive comes back
    /// unchanged, so the callers' own integer conversion is what it was.
    pub(super) fn builtin_number_arg(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        index: u32,
    ) -> Result<Option<Value>, InterpreterError> {
        let Some(value) = self.builtin_arg(args, index)? else {
            return Ok(None);
        };
        let primitive = self.object_to_number_primitive(Some(module), value)?;
        if matches!(primitive, Value::Symbol(_) | Value::BigInt(_)) {
            return Err(InterpreterError::TypeError {
                expected: "value convertible to a number".to_string(),
                got: primitive.type_name().to_string(),
            });
        }
        Ok(Some(primitive))
    }

    /// bd-9vouw.117: a builtin's string argument (a search string, a fill
    /// string) after ToPrimitive with hint "string": an object's toString
    /// runs, and a Symbol is a TypeError (ES2020 7.1.12 ToString).
    pub(super) fn builtin_string_arg(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        index: u32,
    ) -> Result<Option<Value>, InterpreterError> {
        let Some(value) = self.builtin_arg(args, index)? else {
            return Ok(None);
        };
        let primitive = self.object_to_string_primitive(Some(module), value)?;
        if matches!(primitive, Value::Symbol(_)) {
            return Err(Self::symbol_to_string_error());
        }
        Ok(Some(primitive))
    }

    /// The text of a builtin argument that is only read as a string
    /// (Date.parse, the URI functions): ToString, with a missing argument
    /// read as undefined ("undefined"), an object converted as in
    /// `object_to_string_primitive`, and a Symbol a TypeError.
    pub(super) fn builtin_arg_text(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        index: u32,
    ) -> Result<String, InterpreterError> {
        let value = self.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
        let primitive = self.object_to_string_primitive(module, value)?;
        if matches!(primitive, Value::Symbol(_)) {
            return Err(Self::symbol_to_string_error());
        }
        Ok(self.value_to_string(&primitive))
    }

    /// ES2020 7.1.22 ToIndex of a primitive (an object argument has been
    /// through ToPrimitive already): ToIntegerOrInfinity of ToNumber, so NaN
    /// and undefined are 0 and fractions truncate toward zero. A Symbol or
    /// BigInt is the TypeError ToNumber raises. `Ok(None)` is the RangeError
    /// case, an index below 0 or above 2^53 - 1, which the caller reports
    /// with its own message.
    pub(super) fn to_index_value(value: &Value) -> Result<Option<u64>, InterpreterError> {
        if matches!(value, Value::Symbol(_) | Value::BigInt(_)) {
            return Err(InterpreterError::TypeError {
                expected: "value convertible to a number".to_string(),
                got: value.type_name().to_string(),
            });
        }
        let number = Self::coerce_to_float(value).unwrap_or(f64::NAN);
        let integer = if number.is_nan() { 0.0 } else { number.trunc() };
        if !(0.0..=MAX_SAFE_INTEGER as f64).contains(&integer) {
            return Ok(None);
        }
        Ok(Some(integer as u64))
    }

    /// ToNumber's ToPrimitive step (hint "number") for an object, observable
    /// through @@toPrimitive, valueOf and toString. An object that converts
    /// to undefined comes back as NaN, which is ToNumber(undefined), so the
    /// caller does not mistake it for an absent argument. Anything that is
    /// not an object, and any value when there is no module for the guest
    /// call, comes back unchanged.
    pub(super) fn object_to_number_primitive(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        if !value.is_object_like() || module.is_none() {
            return Ok(value);
        }
        Ok(
            match self.coerce_runtime_primitive_with_hint(module, value, "number")? {
                Value::Undefined => Value::Float(Float64::new(f64::NAN)),
                primitive => primitive,
            },
        )
    }

    /// ToString's ToPrimitive step (hint "string") for an object, observable
    /// through @@toPrimitive, toString and valueOf. An object that converts
    /// to undefined comes back as "undefined", which is ToString(undefined),
    /// not an absent argument. Anything that is not an object, and any value
    /// when there is no module for the guest call, comes back unchanged.
    pub(super) fn object_to_string_primitive(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        if !value.is_object_like() || module.is_none() {
            return Ok(value);
        }
        Ok(
            match self.coerce_runtime_primitive_with_hint(module, value, "string")? {
                Value::Undefined => Value::str("undefined"),
                primitive => primitive,
            },
        )
    }

    pub(super) fn primitive_conversion_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        conversion: PrimitiveConversion,
    ) -> Result<Value, InterpreterError> {
        let input = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        // ToBoolean never invokes guest code, including on revoked proxies.
        if matches!(conversion, PrimitiveConversion::Boolean) {
            return Ok(Value::Bool(input.is_truthy()));
        }
        let context = self.join_arg_range_label(args)?;
        let context_bytes = Self::estimate_label_bytes(&context);
        let saved_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        // Reuse the admission-accounted callback scratch component. It remains
        // live across reentrant JSON/conversion calls and memory resyncs.
        self.json_reserve_temporary(saved_bytes)?;
        if let Err(error) = self.apply_memory_component_delta(saved_bytes, context_bytes) {
            self.json_release_temporary(saved_bytes);
            return Err(error);
        }
        let saved_context = self.active_inline_callback_context_label.replace(context);
        let mut outcome = (|| {
            self.json_charge_work()?;
            self.json_observe_reachable_value(&input)?;
            match conversion {
                PrimitiveConversion::PropertyKey => {
                    let key = self.coerce_runtime_property_key(module, input)?;
                    self.conversion_observe_hooks()?;
                    if let Value::Str(text) = &key {
                        self.conversion_charge_text(text.len())?;
                    }
                    Ok(key)
                }
                PrimitiveConversion::Number => {
                    if args.count == 0 {
                        return Ok(Value::Int(0));
                    }
                    let number = self.conversion_to_number(module, input, true)?;
                    Ok(number_value(number))
                }
                PrimitiveConversion::String => {
                    if args.count == 0 {
                        return Ok(Value::str(""));
                    }
                    // Only a direct Symbol argument gets String's descriptive
                    // string exception. An object hook returning Symbol throws.
                    if let Value::Symbol(symbol) = input {
                        let description = self.symbol_description(symbol);
                        let length = description
                            .as_ref()
                            .map_or(0, |text| text.len())
                            .saturating_add("Symbol()".len());
                        // Two concatenations can temporarily retain both
                        // representations of the description and result.
                        self.check_temporary_memory_budget((length as u64).saturating_mul(6))?;
                        self.conversion_charge_text(length)?;
                        return Ok(Value::Str(self.symbol_to_string(symbol)));
                    }
                    Ok(Value::Str(self.conversion_to_string(module, input)?))
                }
                PrimitiveConversion::IsNaN | PrimitiveConversion::IsFinite => {
                    let number = self.conversion_to_number(module, input, false)?;
                    Ok(Value::Bool(
                        if matches!(conversion, PrimitiveConversion::IsNaN) {
                            number.is_nan()
                        } else {
                            number.is_finite()
                        },
                    ))
                }
                PrimitiveConversion::ParseFloat => {
                    let text = self.conversion_to_string(module, input)?;
                    let trimmed = text.trim_start_matches(is_js_whitespace);
                    let end = decimal_prefix_len(trimmed);
                    let number = trimmed[..end].parse::<f64>().unwrap_or(f64::NAN);
                    Ok(number_value(number))
                }
                PrimitiveConversion::ParseInt => {
                    // ToString(input) precedes ToInt32(radix), even when radix
                    // is invalid or throws. Capture no radix hooks early.
                    let text = self.conversion_to_string(module, input)?;
                    let scratch = Self::estimate_js_string_bytes(&text);
                    self.json_reserve_temporary(scratch)?;
                    let parsed = (|| {
                        let radix_value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                        self.json_observe_reachable_value(&radix_value)?;
                        let numeric = self.conversion_to_number(module, radix_value, false)?;
                        Ok(number_value(parse_integer(&text, to_int32(numeric))))
                    })();
                    drop(text);
                    self.json_release_temporary(scratch);
                    parsed
                }
                PrimitiveConversion::Boolean => unreachable!("handled without coercion"),
            }
        })();
        if let Err(error) = self.observe_scoped_callback_result() {
            outcome = Err(error);
        }
        if let Err(error) = &outcome
            && Self::js_catchable_error_name(error).is_some()
        {
            outcome = match self.scoped_native_error(error) {
                Ok(error) | Err(error) => Err(error),
            };
        }
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("nested conversions restore the active callback context");
        if outcome.is_ok() {
            let joined = self.clone_dominant_label_with_temporary_budget(
                &context,
                self.pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public),
                0,
            );
            if let Err(error) =
                joined.and_then(|label| self.replace_pending_hostcall_result_label(Some(label)))
            {
                outcome = Err(error);
            }
        } else if matches!(outcome, Err(InterpreterError::UncaughtException { .. }))
            && let Err(error) = self.join_pending_exception_label(&context)
        {
            outcome = Err(error);
        }
        self.active_inline_callback_context_label = saved_context;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(saved_bytes);
        self.json_release_temporary(saved_bytes);
        outcome
    }

    /// Console is an Internal-clearance sink even when reached through a
    /// first-class builtin. Check live argument/PC and reachable storage labels
    /// before formatting or capturing output, not only the compiler's estimate.
    pub(super) fn check_console_confidentiality(
        &mut self,
        args: RegRange,
        capability: &str,
    ) -> Result<(), InterpreterError> {
        self.check_sink_confidentiality(args, capability, &Label::Internal)
    }

    /// bd-9vouw.8: the same live check for any sink, against the clearance
    /// the static flow check assigns it. Host I/O and process spawn run it
    /// before any effect, so a flow the static analysis missed still stops
    /// at the boundary.
    pub(super) fn check_sink_confidentiality(
        &mut self,
        args: RegRange,
        capability: &str,
        clearance: &Label,
    ) -> Result<(), InterpreterError> {
        let context = self.join_arg_range_label(args)?;
        let saved_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        self.json_reserve_temporary(saved_bytes)?;
        if let Err(error) =
            self.apply_memory_component_delta(saved_bytes, Self::estimate_label_bytes(&context))
        {
            self.json_release_temporary(saved_bytes);
            return Err(error);
        }
        let previous = self.active_inline_callback_context_label.replace(context);
        let outcome = (|| {
            self.json_charge_work()?;
            for offset in 0..args.count {
                let value = self.builtin_arg(args, offset)?.unwrap_or(Value::Undefined);
                self.console_observe_reachable_value(&value)?;
            }
            let label = self.json_parse_context_label()?;
            if !label.can_flow_to(clearance) {
                return Err(InterpreterError::CapabilityDenied {
                    capability: format!("{capability}:confidentiality"),
                });
            }
            Ok(())
        })();
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("console provenance walk retains the active context");
        self.active_inline_callback_context_label = previous;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(saved_bytes);
        self.json_release_temporary(saved_bytes);
        outcome
    }

    fn conversion_observe_hooks(&mut self) -> Result<(), InterpreterError> {
        let label = self.json_parse_context_label()?;
        self.json_observe_label(label)
    }

    fn conversion_charge_text(&mut self, bytes: usize) -> Result<(), InterpreterError> {
        self.check_string_limit(bytes)?;
        // Bound CPU for parsing long attacker-controlled strings even when no
        // bytecode instruction is dispatched inside the native parser.
        for _ in 0..bytes.div_ceil(64) {
            self.json_charge_work()?;
        }
        Ok(())
    }

    /// Runs `conversion` (conversion_to_string / conversion_to_number) for
    /// a builtin step that is not inside an operation already scoping the
    /// inline-callback context (JSON, the conversion builtins,
    /// check_sink_confidentiality). The provenance floor the conversion
    /// records there (json_observe_label) is joined into the pending
    /// hostcall-result label, as primitive_conversion_builtin does, and
    /// cleared. Left set, it outlived the call: after construct_regexp's
    /// ToString of a literal's pattern, every later register write took the
    /// context-joining path (Test262's property-escape harness ran 18% more
    /// instructions once one regex literal had been created). Inside an
    /// enclosing scope the observation accumulates there, as before.
    pub(super) fn scoped_conversion<T>(
        &mut self,
        conversion: impl FnOnce(&mut Self) -> Result<T, InterpreterError>,
    ) -> Result<T, InterpreterError> {
        if self.active_inline_callback_context_label.is_some() {
            return conversion(self);
        }
        let outcome = conversion(self);
        let Some(context) = self.active_inline_callback_context_label.take() else {
            return outcome;
        };
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context));
        let value = outcome?;
        let joined = self.clone_dominant_label_with_temporary_budget(
            &context,
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
            0,
        )?;
        self.replace_pending_hostcall_result_label(Some(joined))?;
        Ok(value)
    }

    pub(super) fn conversion_to_string(
        &mut self,
        module: Option<&Ir3Module>,
        input: Value,
    ) -> Result<JsString, InterpreterError> {
        let primitive = self.coerce_runtime_primitive(module, input, true)?;
        self.conversion_observe_hooks()?;
        let text = match primitive {
            Value::Str(text) => text,
            Value::Int(number) => JsString::from(ryu_js::Buffer::new().format(number as f64)),
            Value::Float(number) => JsString::from(ryu_js::Buffer::new().format(number.inner())),
            Value::BigInt(digits) => {
                self.check_temporary_memory_budget((digits.len() as u64).saturating_mul(3))?;
                JsString::from(digits.as_ref())
            }
            Value::Null => JsString::from("null"),
            Value::Undefined => JsString::from("undefined"),
            Value::Bool(value) => JsString::from(if value { "true" } else { "false" }),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "String-convertible primitive".into(),
                    got: other.type_name().into(),
                });
            }
        };
        self.conversion_charge_text(text.len())?;
        Ok(text)
    }

    pub(super) fn conversion_to_number(
        &mut self,
        module: Option<&Ir3Module>,
        input: Value,
        allow_bigint: bool,
    ) -> Result<f64, InterpreterError> {
        let primitive = self.coerce_runtime_primitive(module, input, false)?;
        self.conversion_observe_hooks()?;
        Ok(match primitive {
            Value::Int(number) => number as f64,
            Value::Float(number) => number.inner(),
            Value::Undefined => f64::NAN,
            Value::Null | Value::Bool(false) => 0.0,
            Value::Bool(true) => 1.0,
            Value::Str(text) => {
                self.conversion_charge_text(text.len())?;
                string_number(&text)
            }
            Value::BigInt(digits) if allow_bigint => {
                self.conversion_charge_text(digits.len())?;
                digits.parse::<f64>().unwrap_or(f64::NAN)
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "Number-convertible primitive".into(),
                    got: other.type_name().into(),
                });
            }
        })
    }
}

fn number_value(value: f64) -> Value {
    // Preserve -0 and avoid retaining extra integer precision in the VM's Int
    // fast path. Values outside the safe-integer envelope stay binary64.
    if value.is_finite()
        && value.fract() == 0.0
        && value.abs() <= 9_007_199_254_740_991.0
        && !(value == 0.0 && value.is_sign_negative())
    {
        Value::Int(value as i64)
    } else {
        Value::Float(Float64::new(value))
    }
}

/// WhiteSpace or LineTerminator (ES2020 11.2, 11.3): U+FEFF counts and
/// U+0085 does not, unlike Rust's `char::is_whitespace`.
pub(super) fn is_js_whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
        | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

/// Longest StrDecimalLiteral prefix. An incomplete exponent is not consumed.
fn decimal_prefix_len(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut pos = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    if text
        .get(pos..)
        .is_some_and(|tail| tail.starts_with("Infinity"))
    {
        return pos + "Infinity".len();
    }
    let start = pos;
    while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        pos += 1;
    }
    let mut digits = pos - start;
    if bytes.get(pos) == Some(&b'.') {
        pos += 1;
        let start = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        digits += pos - start;
    }
    if digits == 0 {
        return 0;
    }
    let mantissa_end = pos;
    if matches!(bytes.get(pos), Some(b'e' | b'E')) {
        pos += 1;
        if matches!(bytes.get(pos), Some(b'+' | b'-')) {
            pos += 1;
        }
        let start = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if pos == start {
            return mantissa_end;
        }
    }
    pos
}

pub(super) fn string_number(text: &JsString) -> f64 {
    let text = text.trim_matches(is_js_whitespace);
    if text.is_empty() {
        return 0.0;
    }
    for (lower, upper, radix) in [("0x", "0X", 16), ("0o", "0O", 8), ("0b", "0B", 2)] {
        if let Some(digits) = text
            .strip_prefix(lower)
            .or_else(|| text.strip_prefix(upper))
        {
            let (number, count) = integer_prefix(digits, radix);
            return if count > 0 && count == digits.len() {
                number
            } else {
                f64::NAN
            };
        }
    }
    if decimal_prefix_len(text) != text.len() {
        return f64::NAN;
    }
    text.parse::<f64>().unwrap_or(f64::NAN)
}

fn to_int32(number: f64) -> i32 {
    if !number.is_finite() || number == 0.0 {
        return 0;
    }
    let unsigned = number.trunc().rem_euclid(4_294_967_296.0) as u32;
    unsigned as i32
}

fn parse_integer(text: &JsString, radix: i32) -> f64 {
    let mut text = text.trim_start_matches(is_js_whitespace);
    let negative = text.starts_with('-');
    if text.starts_with(['+', '-']) {
        text = &text[1..];
    }
    if radix != 0 && !(2..=36).contains(&radix) {
        return f64::NAN;
    }
    let strip_prefix = radix == 0 || radix == 16;
    let mut radix = if radix == 0 { 10 } else { radix as u32 };
    if strip_prefix && (text.starts_with("0x") || text.starts_with("0X")) {
        text = &text[2..];
        radix = 16;
    }
    let (number, count) = integer_prefix(text, radix);
    if count == 0 {
        f64::NAN
    } else if negative {
        -number
    } else {
        number
    }
}

/// Exactly accumulate at most 1024 significant bits. Larger integers always
/// round to Infinity, so no dynamic big-integer allocation is necessary.
fn integer_prefix(text: &str, radix: u32) -> (f64, usize) {
    let mut limbs = [0_u32; 32];
    let mut used = 1;
    let mut overflow = false;
    let mut count = 0;
    for byte in text.bytes() {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'z' => u32::from(byte - b'a') + 10,
            b'A'..=b'Z' => u32::from(byte - b'A') + 10,
            _ => break,
        };
        if digit >= radix {
            break;
        }
        count += 1;
        if overflow {
            continue;
        }
        let mut carry = u64::from(digit);
        for limb in &mut limbs[..used] {
            carry += u64::from(*limb) * u64::from(radix);
            *limb = carry as u32;
            carry >>= 32;
        }
        if carry != 0 {
            if used == limbs.len() {
                overflow = true;
            } else {
                limbs[used] = carry as u32;
                used += 1;
            }
        }
    }
    if overflow {
        return (f64::INFINITY, count);
    }
    let bits = (used - 1) * 32 + (32 - limbs[used - 1].leading_zeros() as usize);
    let shift = bits.saturating_sub(53);
    let bit = |index: usize| (limbs[index / 32] >> (index % 32)) & 1;
    let mut significant = 0_u64;
    for index in (shift..bits).rev() {
        significant = (significant << 1) | u64::from(bit(index));
    }
    if shift > 0
        && bit(shift - 1) != 0
        && (significant & 1 != 0 || (0..shift - 1).any(|index| bit(index) != 0))
    {
        significant += 1;
    }
    (significant as f64 * 2_f64.powi(shift as i32), count)
}

#[cfg(test)]
mod console_confidentiality_tests {
    //! bd-39iih: the console sink's runtime label walk must reach everything
    //! `util.inspect` prints, not only the data edges JSON follows. The heap
    //! is built directly so a runtime-only Secret label is in play (the
    //! lowering refuses statically labeled cases before execution).

    use super::*;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "console-ifc")
    }

    fn object(core: &mut InterpreterCore, prototype: Option<ObjectId>) -> ObjectId {
        core.alloc_object_with_prototype(prototype)
            .expect("allocate object")
    }

    fn secret(core: &mut InterpreterCore, prototype: Option<ObjectId>) -> ObjectId {
        let id = object(core, prototype);
        core.join_direct_object_mutation_label(id, &Label::Secret)
            .expect("label object");
        id
    }

    fn console_allows(core: &mut InterpreterCore, root: ObjectId) -> bool {
        core.set_reg(0, Value::Object(root));
        match core.check_console_confidentiality(RegRange { start: 0, count: 1 }, "console:log") {
            Ok(()) => true,
            Err(InterpreterError::CapabilityDenied { .. }) => false,
            Err(other) => panic!("unexpected console check failure: {other:?}"),
        }
    }

    fn map_with_key(core: &mut InterpreterCore, key: ObjectId) -> ObjectId {
        let map = object(core, None);
        let storage = object(core, None);
        core.set_object_brand(map, "Map").expect("map tag");
        core.set_object_property(map, "__entries".to_string(), Value::Object(storage))
            .expect("map storage");
        core.set_object_property(map, COLLECTION_SIZE_SLOT.to_string(), Value::Int(0))
            .expect("map size");
        core.map_collection_set(map, Value::Object(key), Value::Int(1))
            .expect("map set");
        map
    }

    #[test]
    fn console_walk_reaches_what_inspect_prints() {
        // Controls: no Secret anywhere passes; Secret under an ordinary key
        // is refused (the data edge JSON already follows).
        let mut c = core();
        let public_inner = object(&mut c, None);
        let outer = object(&mut c, None);
        c.set_object_property(outer, "a".to_string(), Value::Object(public_inner))
            .expect("property");
        assert!(
            console_allows(&mut c, outer),
            "all-public object must print"
        );

        let mut c = core();
        let inner = secret(&mut c, None);
        let outer = object(&mut c, None);
        c.set_object_property(outer, "a".to_string(), Value::Object(inner))
            .expect("property");
        assert!(
            !console_allows(&mut c, outer),
            "ordinary key must be refused"
        );

        // Symbol-keyed property (a sidecar `values()` does not visit).
        let mut c = core();
        let inner = secret(&mut c, None);
        let outer = object(&mut c, None);
        c.mutate_heap(|heap| {
            heap[outer.0 as usize]
                .properties
                .insert_baseline_symbol_property(
                    CoreSymbolId(7),
                    BaselineSymbolProperty::Data(Value::Object(inner)),
                );
        });
        assert!(
            !console_allows(&mut c, outer),
            "Symbol-keyed Secret printed"
        );

        // Map key (stored as a key repr, not a value).
        let mut c = core();
        let inner = secret(&mut c, None);
        let map = map_with_key(&mut c, inner);
        assert!(!console_allows(&mut c, map), "Secret Map key printed");
        let mut c = core();
        let inner = object(&mut c, None);
        let map = map_with_key(&mut c, inner);
        assert!(console_allows(&mut c, map), "public Map key must print");

        // Error whose message is inherited from a Secret prototype.
        let mut c = core();
        let error_prototype = c
            .ensure_builtin_prototype("Error")
            .expect("Error.prototype");
        let secret_prototype = secret(&mut c, Some(error_prototype));
        let error = object(&mut c, Some(secret_prototype));
        assert!(
            !console_allows(&mut c, error),
            "inherited Secret error field printed"
        );
        // A non-error object's prototype is not printed: no over-taint.
        let mut c = core();
        let secret_prototype = secret(&mut c, None);
        let plain = object(&mut c, Some(secret_prototype));
        assert!(
            console_allows(&mut c, plain),
            "non-error prototype over-tainted"
        );
    }
}
