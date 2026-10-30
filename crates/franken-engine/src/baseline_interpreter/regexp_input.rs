//! Lossless input for the two native RegExp matchers (bd-9vouw.458).
//!
//! Without `u`/`v`, ECMAScript matches UTF-16 code units. Rust `char` cannot
//! represent surrogate units, so map those 2,048 units to private-use scalar
//! values. Every other unit keeps its scalar value. This is injective: an
//! actual supplementary private-use character is itself encoded as two
//! surrogate units, never as one of the reserved scalars. Patterns use the
//! same mapping. ASCII and BMP text without lone surrogates is borrowed.
//!
//! Encoded text never escapes to JavaScript. Capture values are decoded and
//! offsets are converted to UTF-16 before publication. Unicode mode retains
//! the matchers' existing scalar representation.

use std::borrow::Cow;
use std::cell::Cell;
use std::rc::Rc;

use super::{Captures, InterpreterCore, InterpreterError, JsString};

const SURROGATE_BASE: u32 = 0xF0000;

/// Independent stack owners share one live-byte ledger. A nested execution
/// may resynchronize the core's retained estimate but cannot erase these
/// reservations; each owner releases exactly its own charge on every exit.
struct RegExpTemporaryCharge {
    ledger: Rc<Cell<u64>>,
    bytes: u64,
}

impl Drop for RegExpTemporaryCharge {
    fn drop(&mut self) {
        let previous = self.ledger.get();
        debug_assert!(previous >= self.bytes, "RegExp temporary charge underflow");
        self.ledger.set(previous.saturating_sub(self.bytes));
    }
}

pub(super) fn encode_code_unit(unit: u16) -> char {
    let value = u32::from(unit);
    char::from_u32(if (0xD800..=0xDFFF).contains(&value) {
        SURROGATE_BASE + value - 0xD800
    } else {
        value
    })
    .expect("a UTF-16 unit maps to a valid scalar")
}

pub(super) struct RegExpInput<'a> {
    text: Cow<'a, str>,
    full_unicode: bool,
    ascii: bool,
    // Fields drop in declaration order: release the charge after the text.
    temporary_charge: Option<RegExpTemporaryCharge>,
}

impl<'a> RegExpInput<'a> {
    fn needs_encoding(input: &JsString, full_unicode: bool) -> bool {
        !full_unicode
            && !input.is_ascii()
            && (!input.is_well_formed()
                || input.as_utf8_projection().bytes().any(|byte| byte >= 0xF0))
    }

    fn required_bytes(input: &JsString, full_unicode: bool) -> u64 {
        if !Self::needs_encoding(input, full_unicode) {
            return 0;
        }
        input.encode_utf16().fold(0u64, |bytes, unit| {
            bytes.saturating_add(encode_code_unit(unit).len_utf8() as u64)
        })
    }

    pub(super) fn new(input: &'a JsString, full_unicode: bool) -> Self {
        Self {
            text: Self::encode(input, full_unicode),
            full_unicode,
            ascii: input.is_ascii(),
            temporary_charge: None,
        }
    }

    pub(super) fn encode(input: &JsString, full_unicode: bool) -> Cow<'_, str> {
        if Self::needs_encoding(input, full_unicode) {
            let capacity = usize::try_from(Self::required_bytes(input, full_unicode))
                .expect("an admitted string's encoded length fits usize");
            let mut text = String::with_capacity(capacity);
            text.extend(input.encode_utf16().map(encode_code_unit));
            Cow::Owned(text)
        } else {
            Cow::Borrowed(input.as_utf8_projection())
        }
    }

    pub(super) fn text(&self) -> &str {
        &self.text
    }

    pub(super) fn retained_bytes(&self) -> u64 {
        match &self.text {
            Cow::Borrowed(_) => 0,
            Cow::Owned(text) => text.capacity() as u64,
        }
    }

    pub(super) fn decode(&self, text: &str) -> JsString {
        if self.full_unicode || !text.bytes().any(|byte| byte >= 0xF0) {
            return JsString::from(text);
        }
        let units: Vec<u16> = text
            .chars()
            .map(|character| {
                let value = u32::from(character);
                if (SURROGATE_BASE..SURROGATE_BASE + 0x800).contains(&value) {
                    (value - SURROGATE_BASE + 0xD800) as u16
                } else {
                    // Non-Unicode matching text contains only BMP scalars
                    // and the encoded surrogate interval.
                    u16::try_from(value).expect("encoded RegExp code unit")
                }
            })
            .collect();
        JsString::from_code_units(&units)
    }

    pub(super) fn slice(&self, from: usize, to: usize) -> JsString {
        self.decode(&self.text[from..to])
    }

    pub(super) fn unit_index(&self, byte: usize) -> usize {
        if self.ascii {
            byte
        } else {
            self.unit_length(&self.text[..byte])
        }
    }

    pub(super) fn unit_length(&self, text: &str) -> usize {
        if self.full_unicode {
            text.encode_utf16().count()
        } else {
            text.chars().count()
        }
    }

    pub(super) fn byte_index(&self, index: usize) -> usize {
        if self.ascii {
            return index.min(self.text.len());
        }
        let mut units = 0usize;
        for (offset, character) in self.text.char_indices() {
            if units >= index {
                return offset;
            }
            units += if self.full_unicode {
                character.len_utf16()
            } else {
                1
            };
        }
        self.text.len()
    }

    pub(super) fn unit_spans(&self, spans: &Captures) -> Captures {
        spans
            .iter()
            .map(|span| span.map(|(from, to)| (self.unit_index(from), self.unit_index(to))))
            .collect()
    }
}

/// Replacement text in matcher coordinates, with the guest-visible UTF-8
/// projection length tracked incrementally. Encoded halves may join across
/// appends, so charging the carrier's bytes would reject valid strings near
/// their limit and repeatedly decoding the output would be quadratic.
pub(super) struct RegExpOutput {
    text: String,
    utf8_len: usize,
    pending_high: bool,
    full_unicode: bool,
    temporary_charge: Option<RegExpTemporaryCharge>,
}

impl RegExpOutput {
    pub(super) fn new(capacity: usize, full_unicode: bool) -> Self {
        Self {
            text: String::with_capacity(capacity),
            utf8_len: 0,
            pending_high: false,
            full_unicode,
            temporary_charge: None,
        }
    }

    pub(super) fn text(&self) -> &str {
        &self.text
    }

    fn projected_append(&self, text: &str, max: usize) -> Result<(usize, bool), usize> {
        let mut length = self.utf8_len;
        let mut pending_high = self.pending_high;
        if self.full_unicode || text.is_ascii() {
            length = length.saturating_add(text.len());
            if !text.is_empty() {
                pending_high = false;
            }
        } else {
            for character in text.chars() {
                let value = u32::from(character);
                let unit = if (SURROGATE_BASE..SURROGATE_BASE + 0x800).contains(&value) {
                    value - SURROGATE_BASE + 0xD800
                } else {
                    value
                };
                length =
                    length.saturating_add(if (0xDC00..=0xDFFF).contains(&unit) && pending_high {
                        1 // The previously charged three-byte lone high becomes a four-byte pair.
                    } else if (0xD800..=0xDFFF).contains(&unit) {
                        3
                    } else {
                        character.len_utf8()
                    });
                pending_high = (0xD800..=0xDBFF).contains(&unit);
            }
        }
        if length > max {
            return Err(length);
        }
        Ok((length, pending_high))
    }

    #[cfg(test)]
    pub(super) fn push(&mut self, text: &str, max: usize) -> Result<(), usize> {
        let (length, pending_high) = self.projected_append(text, max)?;
        self.text.push_str(text);
        self.utf8_len = length;
        self.pending_high = pending_high;
        Ok(())
    }
}

impl InterpreterCore {
    fn reserve_regexp_temporary(
        &self,
        bytes: u64,
    ) -> Result<Option<RegExpTemporaryCharge>, InterpreterError> {
        if bytes == 0 {
            return Ok(None);
        }
        self.check_temporary_memory_budget(bytes)?;
        let total = self
            .regexp_temporary_bytes
            .get()
            .checked_add(bytes)
            .expect("admitted RegExp temporary total fits u64");
        self.regexp_temporary_bytes.set(total);
        Ok(Some(RegExpTemporaryCharge {
            ledger: Rc::clone(&self.regexp_temporary_bytes),
            bytes,
        }))
    }

    fn reconcile_regexp_capacity(
        &self,
        charge: &mut Option<RegExpTemporaryCharge>,
        actual: u64,
    ) -> Result<(), InterpreterError> {
        let reserved = charge.as_ref().map_or(0, |charge| charge.bytes);
        if actual == reserved {
            return Ok(());
        }
        if actual > reserved {
            // String guarantees at least the requested capacity. Account for
            // an allocator that exposes extra capacity before publishing it.
            let extra = actual - reserved;
            self.check_temporary_memory_budget(extra)?;
            self.regexp_temporary_bytes.set(
                self.regexp_temporary_bytes
                    .get()
                    .checked_add(extra)
                    .expect("admitted RegExp capacity fits u64"),
            );
        } else {
            self.regexp_temporary_bytes.set(
                self.regexp_temporary_bytes
                    .get()
                    .saturating_sub(reserved - actual),
            );
        }
        if let Some(charge) = charge {
            charge.bytes = actual;
        } else if actual > 0 {
            *charge = Some(RegExpTemporaryCharge {
                ledger: Rc::clone(&self.regexp_temporary_bytes),
                bytes: actual,
            });
        }
        Ok(())
    }

    pub(super) fn prepare_regexp_output(
        &self,
        capacity: usize,
        full_unicode: bool,
    ) -> Result<RegExpOutput, InterpreterError> {
        let mut charge = self.reserve_regexp_temporary(capacity as u64)?;
        let mut output = RegExpOutput::new(capacity, full_unicode);
        self.reconcile_regexp_capacity(&mut charge, output.text.capacity() as u64)?;
        output.temporary_charge = charge;
        Ok(output)
    }

    pub(super) fn append_regexp_output(
        &self,
        output: &mut RegExpOutput,
        text: &str,
    ) -> Result<(), InterpreterError> {
        let (length, pending_high) = output
            .projected_append(text, self.config.max_string_size)
            .map_err(|length| InterpreterError::StringLimitExceeded {
                length,
                max: self.config.max_string_size,
            })?;
        let required = output
            .text
            .len()
            .checked_add(text.len())
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        if required > output.text.capacity() {
            // Grow geometrically when headroom permits. The old buffer stays
            // live during the copy, so admit the whole replacement, not only
            // the capacity difference. Exact growth is a bounded fallback.
            let geometric = output.text.capacity().saturating_mul(2).max(required);
            let capacity = if self.check_temporary_memory_budget(geometric as u64).is_ok() {
                geometric
            } else {
                required
            };
            let mut charge = self.reserve_regexp_temporary(capacity as u64)?;
            let mut replacement = String::with_capacity(capacity);
            self.reconcile_regexp_capacity(&mut charge, replacement.capacity() as u64)?;
            replacement.push_str(&output.text);
            let previous = std::mem::replace(&mut output.text, replacement);
            drop(previous);
            output.temporary_charge = charge;
        }
        output.text.push_str(text);
        output.utf8_len = length;
        output.pending_high = pending_high;
        Ok(())
    }

    pub(super) fn prepare_regexp_input<'a>(
        &self,
        input: &'a JsString,
        full_unicode: bool,
    ) -> Result<RegExpInput<'a>, InterpreterError> {
        let bytes = RegExpInput::required_bytes(input, full_unicode);
        let mut charge = self.reserve_regexp_temporary(bytes)?;
        let mut prepared = RegExpInput::new(input, full_unicode);
        self.reconcile_regexp_capacity(&mut charge, prepared.retained_bytes())?;
        prepared.temporary_charge = charge;
        Ok(prepared)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{InterpreterConfig, RuntimeCapability};
    use super::*;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [RuntimeCapability::HeapAllocate].into_iter().collect();
        InterpreterCore::new(config, "regexp-temporary-reservations")
    }

    #[test]
    fn input_reservations_survive_nested_admission_and_resynchronization() {
        let mut core = core();
        let before = core.estimated_memory_bytes();
        let subject = JsString::from("😀");
        core.config.max_total_memory_bytes = before + 7;
        assert!(matches!(
            core.prepare_regexp_input(&subject, false),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.regexp_temporary_bytes.get(), 0);

        core.config.max_total_memory_bytes = before + 16;
        let outer = core.prepare_regexp_input(&subject, false).unwrap();
        assert_eq!(core.estimated_memory_bytes(), before + 8);
        {
            let inner = core.prepare_regexp_input(&subject, false).unwrap();
            assert_eq!(core.estimated_memory_bytes(), before + 16);
            assert!(matches!(
                core.prepare_regexp_input(&subject, false),
                Err(InterpreterError::MemoryBudgetExceeded { .. })
            ));
            assert!(matches!(
                core.alloc_object_with_prototype(None),
                Err(InterpreterError::MemoryBudgetExceeded { .. })
            ));
            core.sync_estimated_memory_bytes().unwrap();
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
            assert_eq!(inner.retained_bytes(), 8);
        }
        assert_eq!(core.estimated_memory_bytes(), before + 8);
        drop(outer);
        assert_eq!(core.estimated_memory_bytes(), before);
        let borrowed = core.prepare_regexp_input(&subject, true).unwrap();
        assert_eq!(borrowed.retained_bytes(), 0);
        assert_eq!(core.regexp_temporary_bytes.get(), 0);
        core.config.max_total_memory_bytes = u64::MAX;
        core.alloc_object_with_prototype(None).unwrap();
    }

    #[test]
    fn replacement_capacity_growth_is_admitted_before_mutation_and_released() {
        let mut core = core();
        let before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = before + 4;
        let mut output = core.prepare_regexp_output(2, false).unwrap();
        core.append_regexp_output(&mut output, "ab").unwrap();
        assert_eq!(core.estimated_memory_bytes(), before + 2);
        // The old two-byte buffer and the new three-byte minimum overlap.
        assert!(matches!(
            core.append_regexp_output(&mut output, "c"),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(output.text(), "ab");
        assert_eq!(core.estimated_memory_bytes(), before + 2);
        core.config.max_total_memory_bytes = before + 5;
        core.append_regexp_output(&mut output, "c").unwrap();
        assert_eq!(output.text(), "abc");
        assert_eq!(core.estimated_memory_bytes(), before + 3);

        let subject = JsString::from("😀");
        core.config.max_total_memory_bytes = before + 11;
        let nested = core.prepare_regexp_input(&subject, false).unwrap();
        assert!(matches!(
            core.append_regexp_output(&mut output, "d"),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(output.text(), "abc");
        drop(nested);
        core.append_regexp_output(&mut output, "d").unwrap();
        assert_eq!(output.text(), "abcd");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        drop(output);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.regexp_temporary_bytes.get(), 0);
    }

    #[test]
    fn all_units_round_trip_without_private_use_collisions() {
        let units: Vec<u16> = (0..=u16::MAX).collect();
        let input = JsString::from_code_units(&units);
        let encoded = RegExpInput::new(&input, false);
        assert_eq!(encoded.text().chars().count(), units.len());
        assert_eq!(encoded.decode(encoded.text()), input);
        assert_eq!(encoded.unit_index(encoded.text().len()), units.len());
    }

    #[test]
    fn unicode_input_is_borrowed_and_non_unicode_boundaries_are_exact() {
        let input = JsString::from("a😀\u{F0000}b");
        let encoded = RegExpInput::new(&input, false);
        let scalar = RegExpInput::new(&input, true);
        assert!(matches!(scalar.text, Cow::Borrowed(_)));
        for index in 0..=input.utf16_len() {
            assert_eq!(encoded.unit_index(encoded.byte_index(index)), index);
        }
        assert_eq!(
            encoded.slice(encoded.byte_index(2), encoded.byte_index(3)),
            JsString::from_code_units(&[0xDE00])
        );
        for text in ["", "ascii", "é日本\u{E000}"] {
            let text = JsString::from(text);
            assert!(matches!(
                RegExpInput::new(&text, false).text,
                Cow::Borrowed(_)
            ));
        }
    }

    #[test]
    fn replacement_limits_charge_decoded_text_and_healed_boundaries() {
        let high = encode_code_unit(0xD83D).to_string();
        let low = encode_code_unit(0xDE00).to_string();
        let mut output = RegExpOutput::new(0, false);
        output.push(&high, 4).unwrap();
        assert_eq!(output.utf8_len, 3);
        output.push("", 4).unwrap();
        output.push(&low, 4).unwrap();
        assert_eq!(output.utf8_len, 4);
        assert_eq!(output.push("a", 4), Err(5));
        assert_eq!(output.utf8_len, 4);
        let subject = JsString::from("");
        assert_eq!(
            RegExpInput::new(&subject, false).decode(output.text()),
            JsString::from("😀")
        );
    }
}
