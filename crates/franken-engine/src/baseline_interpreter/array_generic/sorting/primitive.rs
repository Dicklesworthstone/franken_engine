//! Default-sort keys borrowed from immutable primitives or formatted on stack.
//!
//! This does not recognize comparators, inspect object shapes, or cache a guest
//! conversion. An object, callable, accessor or Symbol is always a miss, so its
//! observable ToPrimitive/ToString behavior stays on the general sort path.

use super::{JsString, Value};
use std::cmp::Ordering;
use std::fmt::{self, Write};

// Decimal i64 and ECMAScript Number spellings fit comfortably. Keep writes
// fallible anyway: a future formatter change must miss, not truncate or panic.
const KEY_BYTES: usize = 64;

struct KeyBuffer {
    bytes: [u8; KEY_BYTES],
    used: usize,
}

impl KeyBuffer {
    fn new() -> Self {
        Self {
            bytes: [0; KEY_BYTES],
            used: 0,
        }
    }

    fn text(&self) -> &str {
        // Only fmt::Write::write_str populates this range, in complete UTF-8
        // chunks. No unsafe conversion or lossy projection is needed.
        std::str::from_utf8(&self.bytes[..self.used]).expect("formatted UTF-8 chunks")
    }
}

impl Write for KeyBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.used.checked_add(text.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.used..end).ok_or(fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.used = end;
        Ok(())
    }
}

enum Key<'a> {
    Exact(&'a JsString),
    Utf8(&'a str),
}

fn key<'a>(value: &'a Value, buffer: &'a mut KeyBuffer) -> Option<Key<'a>> {
    let text = match value {
        // Rope comparison can allocate traversal frontiers. Keep its existing
        // temporary admission path rather than treating it as stack-only.
        Value::Str(text) if text.concat_parts().nodes == 0 => return Some(Key::Exact(text)),
        Value::BigInt(digits) => digits.as_ref(),
        Value::Undefined => "undefined",
        Value::Null => "null",
        Value::Bool(true) => "true",
        Value::Bool(false) => "false",
        Value::Int(value) => {
            write!(buffer, "{value}").ok()?;
            buffer.text()
        }
        Value::Float(value) => {
            // Use the engine's existing Float64 Display: this preserves -0,
            // NaN, infinities, shortest decimals and JS exponent thresholds.
            write!(buffer, "{value}").ok()?;
            buffer.text()
        }
        _ => return None,
    };
    Some(Key::Utf8(text))
}

/// The exact comparison formerly performed by materializing two JsStrings.
/// None requires the original observable conversion path. The caller owns
/// dispatch/work metering and observation; this helper never calls guest code.
/// Undefined-last ordering belongs to CompareArrayElements, not ToString.
pub(super) fn compare(left: &Value, right: &Value) -> Option<Ordering> {
    let mut left_buffer = KeyBuffer::new();
    let mut right_buffer = KeyBuffer::new();
    let left = key(left, &mut left_buffer)?;
    let right = key(right, &mut right_buffer)?;
    Some(match (left, right) {
        (Key::Exact(left), Key::Exact(right)) => left.utf16_cmp(right),
        (Key::Exact(left), Key::Utf8(right)) => left.encode_utf16().cmp(right.encode_utf16()),
        (Key::Utf8(left), Key::Exact(right)) => left.encode_utf16().cmp(right.encode_utf16()),
        (Key::Utf8(left), Key::Utf8(right)) => {
            if left.is_ascii() && right.is_ascii() {
                left.cmp(right)
            } else {
                // Preserve the existing behavior even for a foreign Rust
                // caller constructing a noncanonical BigInt text payload.
                left.encode_utf16().cmp(right.encode_utf16())
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{InterpreterConfig, InterpreterCore, InterpreterError, Label, ObjectId, RuntimeCapability};
    use std::sync::Arc;

    fn reference(core: &InterpreterCore, value: &Value) -> JsString {
        match value {
            Value::Str(text) => text.clone(),
            other => JsString::from(core.value_to_string(other)),
        }
    }

    #[test]
    fn primitive_pairs_match_materialized_exact_utf16_keys() {
        let core = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "sort-keys");
        let mut values = vec![
            Value::Undefined,
            Value::Null,
            Value::Bool(false),
            Value::Bool(true),
            Value::Int(i64::MIN),
            Value::Int(i64::MAX),
            Value::Int(0),
            Value::Int(10),
            Value::Int(2),
            Value::BigInt(Arc::from("1234567890123456789012345678901234567890")),
            Value::BigInt(Arc::from("-1234567890123456789012345678901234567890")),
            // The fast path does not assume a host-constructed BigInt is ASCII.
            Value::BigInt(Arc::from("\u{1f600}")),
            Value::BigInt(Arc::from("\u{e000}")),
        ];
        for text in ["", "0", "00", "false", "null", "undefined", "\u{e9}", "\u{1f600}", "\u{e000}"] {
            values.push(Value::Str(JsString::from(text)));
        }
        for units in [&[0xd800][..], &[0xdc00], &[0xd83d, 0xde00, 0xd800]] {
            values.push(Value::Str(JsString::from_code_units(units)));
        }
        for number in [
            -0.0, 0.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY,
            f64::MAX, f64::MIN_POSITIVE, f64::from_bits(1),
            -1e-7, 1e-6, 1e20, 1e21, 0.1, 9007199254740992.0,
        ] {
            values.push(Value::Float(number.into()));
        }
        for left in &values {
            for right in &values {
                let expected = reference(&core, left).utf16_cmp(&reference(&core, right));
                assert_eq!(compare(left, right), Some(expected), "{left:?} vs {right:?}");
            }
        }
    }

    #[test]
    fn arbitrary_float_bits_and_integer_extremes_use_the_existing_formatter() {
        let core = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "sort-format");
        let mut bits = 0x6a09e667f3bcc909_u64;
        for _ in 0..16384 {
            bits = bits.wrapping_mul(6364136223846793005).wrapping_add(1);
            for value in [Value::Float(f64::from_bits(bits).into()), Value::Int(bits as i64)] {
                let mut buffer = KeyBuffer::new();
                let Some(Key::Utf8(text)) = key(&value, &mut buffer) else {
                    panic!("current primitive formatter must fit its bounded buffer");
                };
                assert_eq!(text, core.value_to_string(&value));
            }
        }
    }

    #[test]
    fn immutable_string_and_bigint_keys_borrow_the_existing_payload() {
        let text = Value::Str(JsString::from_code_units(&[0x61, 0xd800]));
        let digits = Value::BigInt(Arc::from("9".repeat(32768)));
        let mut buffer = KeyBuffer::new();
        let Value::Str(original) = &text else { unreachable!() };
        let Some(Key::Exact(borrowed)) = key(&text, &mut buffer) else { panic!("exact key") };
        assert!(std::ptr::eq(borrowed, original));
        let Value::BigInt(original) = &digits else { unreachable!() };
        let Some(Key::Utf8(borrowed)) = key(&digits, &mut buffer) else { panic!("decimal key") };
        assert_eq!(borrowed.as_ptr(), original.as_ptr());
        assert_eq!(borrowed.len(), original.len());
        assert_eq!(buffer.used, 0);
    }

    #[test]
    fn objects_and_callable_carriers_are_never_treated_as_primitive_keys() {
        for value in [
            Value::Object(ObjectId(0)), Value::Function(0), Value::Closure(0),
            Value::Iterator(0), Value::Generator(0), Value::Promise(0),
        ] {
            assert!(compare(&value, &Value::Int(1)).is_none());
            assert!(compare(&Value::Int(1), &value).is_none());
        }
    }

    #[test]
    fn concatenations_keep_the_existing_traversal_scratch_admission_path() {
        let text = JsString::from("a".repeat(2048)).concat(&JsString::from("b".repeat(2048)));
        assert!(text.concat_parts().nodes > 0);
        let value = Value::Str(text);
        assert!(compare(&value, &Value::Int(1)).is_none());
        assert!(compare(&Value::Int(1), &value).is_none());
        assert!(compare(&value, &value).is_none());
    }

    #[test]
    fn native_primitive_comparisons_need_no_additional_heap_headroom() {
        for mut config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch, RuntimeCapability::HeapAllocate, RuntimeCapability::Builtin,
            ].into_iter().collect();
            let mut core = InterpreterCore::new(config, "sort-borrowed-budget");
            core.json_observe_label(Label::Public).unwrap();
            core.write_reg(0, Value::Str(JsString::from("a".repeat(4096)))).unwrap();
            core.write_reg(1, Value::Str(JsString::from("b".repeat(4096)))).unwrap();
            core.write_reg(2, Value::BigInt(Arc::from("9".repeat(4096)))).unwrap();
            core.write_reg(3, Value::BigInt(Arc::from("1".repeat(4096)))).unwrap();
            let before = core.recompute_estimated_memory_bytes();
            assert_eq!(core.estimated_memory_bytes(), before);
            core.config.max_total_memory_bytes = before;
            for (left, right, expected) in [(0, 1, Ordering::Less), (2, 3, Ordering::Greater)] {
                let a = core.read_reg(left).unwrap();
                let b = core.read_reg(right).unwrap();
                let reads = core.native_hole_reads.get();
                assert_eq!(core.generic_sort_compare(None, a, b, &Value::Undefined).unwrap(), expected);
                assert_eq!(core.native_hole_reads.get(), reads + 1);
                assert_eq!(core.json_parse_temporary_bytes, 0);
                assert_eq!(core.estimated_memory_bytes(), before);
                assert_eq!(core.recompute_estimated_memory_bytes(), before);
            }
            // Borrowing key storage does not bypass comparison fuel admission.
            core.config.instruction_budget = core.instructions_executed + core.native_hole_reads.get();
            assert!(matches!(
                core.generic_sort_compare(None, Value::Int(2), Value::Int(10), &Value::Undefined),
                Err(InterpreterError::BudgetExhausted { .. })
            ));
        }
    }

    #[test]
    fn native_primitive_comparison_retains_pending_callback_observations() {
        let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "sort-observation");
        core.json_observe_label(Label::Public).unwrap();
        core.replace_pending_hostcall_result_label(Some(Label::Secret)).unwrap();
        assert_eq!(
            core.compare_sort_strings(None, Value::Int(2), Value::Int(10)).unwrap(),
            Ordering::Greater
        );
        assert_eq!(core.active_inline_callback_context_label, Some(Label::Secret));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn stack_buffer_rejects_overflow_without_truncation_or_partial_write() {
        let mut buffer = KeyBuffer::new();
        buffer.write_str("\u{e9}").unwrap();
        let before = buffer.text().to_owned();
        assert!(buffer.write_str(&"x".repeat(KEY_BYTES)).is_err());
        assert_eq!(buffer.text(), before);
        buffer.write_str(&"x".repeat(KEY_BYTES - 2)).unwrap();
        assert_eq!(buffer.used, KEY_BYTES);
        assert!(buffer.write_char('!').is_err());
        assert_eq!(buffer.used, KEY_BYTES);
    }
}
