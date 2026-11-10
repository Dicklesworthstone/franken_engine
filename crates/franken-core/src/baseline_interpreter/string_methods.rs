//! Native String search and slicing through ordinary, receiver-sensitive calls.
//!
//! ES2020 21.1.3: offsets are UTF-16 code units. Observable conversions run
//! before native work and use the same labeled guest-call boundary as arrays.

use super::*;
use crate::ifc_artifacts::Label;

impl InterpreterCore {
    pub(super) fn dispatch_string_method(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        receiver: Option<&Value>,
        args: RegRange,
        mut label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        let outcome = (|| {
            let receiver = receiver.cloned().unwrap_or(Value::Undefined);
            if receiver.is_nullish() {
                return Err(InterpreterError::TypeError {
                    expected: "object-coercible String method receiver".into(),
                    got: receiver.type_name().into(),
                });
            }
            self.charge_array_method_step()?;
            let text = self.array_method_to_string(module, receiver, &mut label)?;
            // A receiver's toString may return a fresh allocation. Keep it
            // accounted while search/start/end coercions execute guest code.
            let bytes = Self::estimate_js_string_bytes(&text);
            self.with_array_method_temporary(bytes, |core| match kind {
                BuiltinFunctionKind::StringPrototypeSlice
                | BuiltinFunctionKind::StringPrototypeSubstring => {
                    core.string_method_slice(module, kind, &text, args, &mut label)
                }
                _ => core.string_method_search(module, kind, &text, args, &mut label),
            })
        })();
        self.finish_native_builtin_call(outcome, label)
    }

    fn string_method_slice(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        text: &JsString,
        args: RegRange,
        label: &mut Label,
    ) -> Result<Value, InterpreterError> {
        let length = text.utf16_len();
        let (start, start_label) = self.promise_hostcall_argument(args, 0)?;
        *label = label.join(&start_label);
        let start = self.native_method_to_number(module, start, label)?;
        let (end, end_label) = self.promise_hostcall_argument(args, 1)?;
        *label = label.join(&end_label);
        let end = if matches!(end, Value::Undefined) {
            length as f64
        } else {
            self.native_method_to_number(module, end, label)?
        };
        let (start, end) = if kind == BuiltinFunctionKind::StringPrototypeSlice {
            let start = relative_string_position(start, length);
            (start, relative_string_position(end, length).max(start))
        } else {
            let start = clamped_string_position(start, length);
            let end = clamped_string_position(end, length);
            (start.min(end), start.max(end))
        };
        if start == end {
            return Ok(Value::Str(JsString::empty()));
        }
        self.charge_string_method_work(length as u64)?;
        // Slicing can split a surrogate pair and settle a rope. Admit the
        // source projection, exact-unit output, and traversal allocations first.
        let scratch = string_traversal_bytes(text)
            .saturating_add(text.len() as u64)
            .saturating_add(((end - start) as u64).saturating_mul(8))
            .saturating_add(256);
        self.check_temporary_memory_budget(scratch)?;
        let result = text.utf16_slice(start, end);
        self.check_string_limit(result.len())?;
        Ok(Value::Str(result))
    }

    fn string_method_search(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        text: &JsString,
        args: RegRange,
        label: &mut Label,
    ) -> Result<Value, InterpreterError> {
        let (search, search_label) = self.promise_hostcall_argument(args, 0)?;
        *label = label.join(&search_label);
        if matches!(
            kind,
            BuiltinFunctionKind::StringPrototypeIncludes
                | BuiltinFunctionKind::StringPrototypeStartsWith
                | BuiltinFunctionKind::StringPrototypeEndsWith
        ) && search.is_object_like()
        {
            // IsRegExp is observable even for ordinary objects. Core has no
            // native RegExp internal slot; @@match is its executable hook.
            let matcher = self.read_iterator_property(
                module,
                &search,
                &RuntimePropertyKey::Symbol(WellKnownSymbol::Match.id()),
                label,
            )?;
            if matcher.is_truthy() {
                return Err(InterpreterError::TypeError {
                    expected: "non-RegExp String search argument".into(),
                    got: "truthy Symbol.match".into(),
                });
            }
        }
        let search = self.array_method_to_string(module, search, label)?;
        let bytes = Self::estimate_js_string_bytes(&search);
        self.with_array_method_temporary(bytes, |core| {
            let (position, position_label) = core.promise_hostcall_argument(args, 1)?;
            *label = label.join(&position_label);
            let number = if kind == BuiltinFunctionKind::StringPrototypeEndsWith
                && matches!(position, Value::Undefined)
            {
                text.utf16_len() as f64
            } else {
                core.native_method_to_number(module, position, label)?
            };
            // lastIndexOf uniquely treats NaN (including undefined) as
            // +Infinity; other methods' ToInteger converts NaN to zero.
            let number =
                if kind == BuiltinFunctionKind::StringPrototypeLastIndexOf && number.is_nan() {
                    f64::INFINITY
                } else {
                    number
                };
            let position = clamped_string_position(number, text.utf16_len());
            let needle_length = search.utf16_len();
            if needle_length != 0 {
                core.charge_string_method_work(
                    (text.utf16_len() as u64).saturating_add(needle_length as u64),
                )?;
                // Well-formed rope matching sizes its failure table in UTF-8
                // bytes, while exact-unit matching uses UTF-16 units. Admit
                // the larger alternative, including its gathered pattern;
                // multibyte BMP needles can need three bytes for every unit.
                let entry_bytes = std::mem::size_of::<usize>() as u64;
                let byte_pattern = (search.len() as u64).saturating_mul(1 + entry_bytes);
                let unit_pattern = (needle_length as u64).saturating_mul(2 + entry_bytes);
                let scratch = string_traversal_bytes(text)
                    .saturating_add(string_traversal_bytes(&search))
                    .saturating_add(byte_pattern.max(unit_pattern));
                core.check_temporary_memory_budget(scratch)?;
            }
            let result = match kind {
                BuiltinFunctionKind::StringPrototypeIndexOf => Value::Int(
                    text.utf16_index_of(&search, position)
                        .map_or(-1, |index| index as i64),
                ),
                BuiltinFunctionKind::StringPrototypeLastIndexOf => Value::Int(
                    text.utf16_last_index_of(&search, position)
                        .map_or(-1, |index| index as i64),
                ),
                BuiltinFunctionKind::StringPrototypeIncludes => {
                    Value::Bool(text.utf16_index_of(&search, position).is_some())
                }
                BuiltinFunctionKind::StringPrototypeStartsWith => Value::Bool(
                    needle_length <= text.utf16_len() - position
                        && string_matches_at(text, &search, position),
                ),
                BuiltinFunctionKind::StringPrototypeEndsWith => Value::Bool(
                    needle_length <= position
                        && string_matches_at(text, &search, position - needle_length),
                ),
                _ => unreachable!("String search dispatcher accepts only search methods"),
            };
            Ok(result)
        })
    }

    /// Number coercion shared by native string positions and array-like lengths.
    pub(super) fn native_method_to_number(
        &mut self,
        module: &Ir3Module,
        value: Value,
        label: &mut Label,
    ) -> Result<f64, InterpreterError> {
        let value = self.array_method_to_primitive(module, value, false, label)?;
        match value {
            Value::Symbol(_) => Err(InterpreterError::TypeError {
                expected: "numeric native method argument".into(),
                got: "symbol".into(),
            }),
            Value::Str(text) => {
                self.charge_string_method_work(text.utf16_len() as u64)?;
                self.with_array_method_temporary(Self::estimate_js_string_bytes(&text), |core| {
                    core.check_temporary_memory_budget(
                        (text.len() as u64).saturating_add(string_traversal_bytes(&text)),
                    )?;
                    Ok(text.as_str().map_or(f64::NAN, string_position_number))
                })
            }
            value => Ok(Self::coerce_to_float(&value).unwrap_or(f64::NAN)),
        }
    }

    fn charge_string_method_work(&mut self, units: u64) -> Result<(), InterpreterError> {
        if self
            .config
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(InterpreterError::Cancelled);
        }
        if units
            > self
                .config
                .instruction_budget
                .saturating_sub(self.instructions_executed)
        {
            self.instructions_executed = self.config.instruction_budget;
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        self.instructions_executed += units;
        Ok(())
    }
}

fn string_traversal_bytes(text: &JsString) -> u64 {
    // Search cursors retain an offset beside each rope node; slicing may
    // retain two. Include geometric Vec growth and the boxed iterator cursor.
    (text.concat_parts().nodes as u64)
        .saturating_add(1)
        .saturating_mul((std::mem::size_of::<(JsString, usize, usize)>() as u64).saturating_mul(4))
        .saturating_add(256)
}

fn string_matches_at(text: &JsString, search: &JsString, start: usize) -> bool {
    search.is_empty()
        || text
            .encode_utf16()
            .skip(start)
            .take(search.utf16_len())
            .eq(search.encode_utf16())
}

fn clamped_string_position(number: f64, length: usize) -> usize {
    if number.is_nan() || number <= 0.0 {
        0
    } else {
        number.trunc().min(length as f64) as usize
    }
}

fn relative_string_position(number: f64, length: usize) -> usize {
    if number < 0.0 {
        (length as f64 + number.trunc()).max(0.0) as usize
    } else {
        clamped_string_position(number, length)
    }
}

// StringNumericLiteral for positions. Rust's float parser accepts "inf" and
// case-insensitive infinity; ECMAScript rejects those spellings. Rust trim
// additionally removes U+0085, which ECMAScript does not.
fn string_position_number(text: &str) -> f64 {
    let text = text.trim_matches(|c| {
        matches!(
            c,
            '\u{0009}'..='\u{000d}'
                | '\u{0020}'
                | '\u{00a0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
        )
    });
    match text {
        "" => return 0.0,
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if let Some((radix, digits)) = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map(|digits| (16, digits))
        .or_else(|| {
            text.strip_prefix("0b")
                .or_else(|| text.strip_prefix("0B"))
                .map(|digits| (2, digits))
        })
        .or_else(|| {
            text.strip_prefix("0o")
                .or_else(|| text.strip_prefix("0O"))
                .map(|digits| (8, digits))
        })
    {
        if digits.is_empty() {
            return f64::NAN;
        }
        let mut value = 0.0;
        for digit in digits.chars() {
            let Some(digit) = digit.to_digit(radix) else {
                return f64::NAN;
            };
            value = value * f64::from(radix) + f64::from(digit);
        }
        return value;
    }
    let bytes = text.as_bytes();
    let mut offset = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let mut digits = 0;
    while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
        offset += 1;
        digits += 1;
    }
    if bytes.get(offset) == Some(&b'.') {
        offset += 1;
        while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return f64::NAN;
    }
    if matches!(bytes.get(offset), Some(b'e' | b'E')) {
        offset += 1;
        offset += usize::from(matches!(bytes.get(offset), Some(b'+' | b'-')));
        let start = offset;
        while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        if start == offset {
            return f64::NAN;
        }
    }
    if offset != bytes.len() {
        return f64::NAN;
    }
    text.parse().unwrap_or(f64::NAN)
}
