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
}

impl InterpreterCore {
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

    fn conversion_to_string(
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

    fn conversion_to_number(
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

fn is_js_whitespace(c: char) -> bool {
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
