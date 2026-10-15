//! Bounded UTF-16 output and allocation-free JSON escaping.
//!
//! A batch may use only slots already admitted by the scalar writer and may
//! not cross the next work checkpoint. Three projected bytes per code unit
//! is a safe upper bound even for lone surrogates; a healed pair needs four
//! bytes across its two units. Near a limit, the scalar writer still decides
//! the precise failing unit and preserves the partially written prefix.

use std::iter::{Fuse, FusedIterator, Peekable};

use super::{InterpreterCore, InterpreterError, StringifyState};

// Most keys and values have only a few outstanding rope branches. Keep
// those references on the stack instead of allocating a Vec for every
// string in a document. Deep trees spill through the same admitted growth
// path; this fixed stack storage is not a retained cache or a heap charge.
const INLINE_STRING_PARTS: usize = 8;

struct StringParts {
    inline: [Option<super::JsString>; INLINE_STRING_PARTS],
    inline_len: usize,
    spill: Vec<super::JsString>,
}

impl Default for StringParts {
    fn default() -> Self {
        Self {
            inline: std::array::from_fn(|_| None),
            inline_len: 0,
            spill: Vec::new(),
        }
    }
}

impl StringParts {
    fn pop(&mut self) -> Option<super::JsString> {
        if let Some(part) = self.spill.pop() {
            return Some(part);
        }
        self.inline_len = self.inline_len.checked_sub(1)?;
        // Taking the slot drops its ownership now, not at the end of the
        // document. A drained frontier never keeps a previously read leaf.
        self.inline[self.inline_len].take()
    }
}

impl StringifyState {
    pub(super) fn quote_contents(
        &mut self,
        core: &mut InterpreterCore,
        text: &super::JsString,
    ) -> Result<(), InterpreterError> {
        self.emit_string::<true>(core, text)
    }

    /// Emit an already-validated raw JSON lexeme, without quoting, escaping or
    /// converting its number spelling. Validation stays with JSON.rawJSON;
    /// this output path shares the quoted writer's admitted rope traversal.
    pub(super) fn raw_text(
        &mut self,
        core: &mut InterpreterCore,
        text: &super::JsString,
    ) -> Result<(), InterpreterError> {
        self.emit_string::<false>(core, text)
    }

    fn emit_string<const QUOTED: bool>(
        &mut self,
        core: &mut InterpreterCore,
        text: &super::JsString,
    ) -> Result<(), InterpreterError> {
        if let Some(parts) = text.unjoined_concat_children() {
            self.emit_rope::<QUOTED>(core, parts)
        } else {
            self.emit_leaf::<QUOTED>(core, text)
        }
    }

    /// Emit the contents of one flat/published leaf, without adding quotes.
    /// Exact-only strings are flat; unresolved concatenations are handled by
    /// emit_rope so the ASCII fast path cannot eagerly join an entire input.
    fn emit_leaf<const QUOTED: bool>(
        &mut self,
        core: &mut InterpreterCore,
        text: &super::JsString,
    ) -> Result<(), InterpreterError> {
        if text.is_ascii() {
            let bytes = text.as_str().expect("ASCII has an exact str view").as_bytes();
            if QUOTED {
                self.quote_ascii(core, bytes)
            } else {
                self.ascii(core, bytes)
            }
        } else if QUOTED {
            if let Some(text) = text.as_str() {
                self.quote_utf8(core, text)
            } else {
                self.units(core, QuotedUnits::new(text.encode_utf16()))
            }
        } else {
            self.units(core, text.encode_utf16())
        }
    }

    /// In well-formed UTF-8, every JSON escape starts with an ASCII byte.
    /// Pass clean spans directly to the existing output writers instead of
    /// testing each decoded unit for escapes and surrogate pairing. Bound
    /// each probe to 256 bytes, and round its end back to a scalar boundary;
    /// neither a pair nor a UTF-8 scalar can be split between spans.
    /// Exact-only strings keep QuotedUnits so lone surrogates stay distinct.
    fn quote_utf8(
        &mut self,
        core: &mut InterpreterCore,
        mut text: &str,
    ) -> Result<(), InterpreterError> {
        while !text.is_empty() {
            let window = text.len().min(256);
            let mut plain = text.as_bytes()[..window]
                .iter()
                .position(|&byte| byte < 0x20 || byte == b'"' || byte == b'\\')
                .unwrap_or(window);
            while !text.is_char_boundary(plain) {
                plain -= 1;
            }
            if plain != 0 {
                let span = &text[..plain];
                if span.is_ascii() {
                    self.ascii(core, span.as_bytes())?;
                } else {
                    self.units(core, span.encode_utf16())?;
                }
                text = &text[plain..];
            } else {
                // A zero-length plain span can only mean an ASCII escape.
                // Reuse its original spelling and scalar admission path.
                self.quote_ascii(core, &text.as_bytes()[..1])?;
                text = &text[1..];
            }
        }
        Ok(())
    }

    /// Traverse unresolved strings by leaf instead of materializing their
    /// complete UTF-8 text or dispatching the rope cursor for every code unit.
    /// Only outstanding right children occupy the admitted frontier. No guest
    /// callback runs, and all existing output work/size/allocation gates remain
    /// in the leaf writer. Additional checkpoints bound structural traversal,
    /// including a deep left spine before any leaf has produced output.
    fn emit_rope<const QUOTED: bool>(
        &mut self,
        core: &mut InterpreterCore,
        parts: [super::JsString; 2],
    ) -> Result<(), InterpreterError> {
        let mut pending = StringParts::default();
        let mut scratch = 0;
        let [left, right] = parts;
        let outcome = (|| {
            core.json_charge_work()?;
            self.push_string_part(core, &mut pending, right, &mut scratch)?;
            let mut current = left;
            let mut remaining = 256;
            loop {
                if remaining == 0 {
                    core.json_charge_work()?;
                    remaining = 256;
                }
                remaining -= 1;
                if let Some([left, right]) = current.unjoined_concat_children() {
                    self.push_string_part(core, &mut pending, right, &mut scratch)?;
                    current = left;
                    continue;
                }
                // A concurrent publisher may replace children with a flat
                // buffer, but never the reverse. This view cannot start a join.
                self.emit_leaf::<QUOTED>(core, &current)?;
                let Some(next) = pending.pop() else {
                    return Ok(());
                };
                current = next;
            }
        })();
        // Drop all references/capacity before releasing this walk's charge.
        // The output, enclosing frames and any inherited scratch stay charged.
        drop(pending);
        self.release(core, scratch);
        outcome
    }

    fn push_string_part(
        &mut self,
        core: &mut InterpreterCore,
        pending: &mut StringParts,
        part: super::JsString,
        scratch: &mut u64,
    ) -> Result<(), InterpreterError> {
        if pending.inline_len < INLINE_STRING_PARTS {
            debug_assert!(pending.spill.is_empty());
            pending.inline[pending.inline_len] = Some(part);
            pending.inline_len += 1;
            return Ok(());
        }
        // Inline references form the bottom of the LIFO stack. Never migrate
        // or clone them on spill, and retain paid spill capacity until drop.
        let pending = &mut pending.spill;
        if pending.len() == pending.capacity() {
            let previous = pending.capacity();
            let additional = previous.max(4);
            let slot = std::mem::size_of::<super::JsString>() as u64;
            let growth = u64::try_from(additional)
                .ok()
                .and_then(|count| count.checked_mul(slot))
                .ok_or_else(|| core.memory_budget_error(u64::MAX, core.heap_object_count_u32()))?;
            self.reserve(core, growth)?;
            *scratch += growth;
            pending.try_reserve_exact(additional).map_err(|_| {
                core.memory_budget_error(u64::MAX, core.heap_object_count_u32())
            })?;
            let retained = u64::try_from(pending.capacity() - previous)
                .ok()
                .and_then(|count| count.checked_mul(slot))
                .ok_or_else(|| core.memory_budget_error(u64::MAX, core.heap_object_count_u32()))?;
            if retained > growth {
                // Allocators may expose more capacity than requested. Admit
                // that difference too before the next traversal/output step.
                self.reserve(core, retained - growth)?;
                *scratch += retained - growth;
            }
        }
        pending.push(part);
        Ok(())
    }

    pub(super) fn units(
        &mut self,
        core: &mut InterpreterCore,
        units: impl Iterator<Item = u16>,
    ) -> Result<(), InterpreterError> {
        let mut units = units.fuse();
        while let Some(first) = units.next() {
            // Only push can allocate, charge work, check cancellation, or
            // refuse a size limit. Keep those gates in their original order.
            self.push(core, first)?;
            let remainder = self.output.len() % 256;
            let until_checkpoint = if remainder == 0 { 0 } else { 256 - remainder };
            let available = self.output.capacity() - self.output.len();
            let below_limit = core
                .config
                .max_string_size
                .saturating_sub(self.projection_bytes)
                / 3;
            let count = available.min(until_checkpoint).min(below_limit);
            let mut previous = first;
            for unit in units.by_ref().take(count) {
                let added = match unit {
                    0..=0x7f => 1,
                    0x80..=0x7ff => 2,
                    0xdc00..=0xdfff if (0xd800..=0xdbff).contains(&previous) => 1,
                    _ => 3,
                };
                // count * 3 fits the remaining byte limit, so this cannot
                // overflow or cross that limit, including at usize::MAX.
                self.projection_bytes += added;
                self.output.push(unit);
                previous = unit;
            }
        }
        Ok(())
    }
}

/// The contents of a quoted JSON string (the caller emits the two quotes).
/// Retain at most the remainder of one escape or the low half of one pair.
/// No scratch vector, scalar decode/re-encode, or input-sized scan is needed.
pub(super) struct QuotedUnits<I: Iterator<Item = u16>> {
    source: Peekable<Fuse<I>>,
    pending: [u16; 5],
    next: usize,
    end: usize,
}

impl<I: Iterator<Item = u16>> QuotedUnits<I> {
    pub(super) fn new(source: I) -> Self {
        Self {
            source: source.fuse().peekable(),
            pending: [0; 5],
            next: 0,
            end: 0,
        }
    }

    fn escaped(&mut self, unit: u16) -> u16 {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.pending[0] = u16::from(b'u');
        for (index, shift) in [12, 8, 4, 0].into_iter().enumerate() {
            self.pending[index + 1] = u16::from(HEX[usize::from((unit >> shift) & 0xf)]);
        }
        self.end = 5;
        u16::from(b'\\')
    }
}

impl<I: Iterator<Item = u16>> Iterator for QuotedUnits<I> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        if self.next < self.end {
            let unit = self.pending[self.next];
            self.next += 1;
            return Some(unit);
        }
        self.next = 0;
        self.end = 0;
        let unit = self.source.next()?;
        let short = match unit {
            0x22 => b'"',
            0x5c => b'\\',
            0x08 => b'b',
            0x0c => b'f',
            0x0a => b'n',
            0x0d => b'r',
            0x09 => b't',
            0x00..=0x1f | 0xdc00..=0xdfff => return Some(self.escaped(unit)),
            0xd800..=0xdbff => {
                if let Some(low) = self.source.next_if(|low| (0xdc00..=0xdfff).contains(low)) {
                    // A pair is literal JSON text; the pending low half must
                    // not re-enter the lone-surrogate escape case above.
                    self.pending[0] = low;
                    self.end = 1;
                    return Some(unit);
                }
                return Some(self.escaped(unit));
            }
            _ => return Some(unit),
        };
        self.pending[0] = u16::from(short);
        self.end = 1;
        Some(u16::from(b'\\'))
    }
}

impl<I: Iterator<Item = u16>> FusedIterator for QuotedUnits<I> {}

#[cfg(test)]
mod frontier_tests {
    use super::super::{InterpreterConfig, JsString, RuntimeCapability};
    use super::*;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "json-inline-frontier")
    }

    fn release(core: &mut InterpreterCore, state: StringifyState) {
        let charged = state.charged;
        drop(state);
        core.json_release_temporary(charged);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn inline_frontier_uses_no_heap_headroom_and_relinquishes_each_leaf() {
        let mut core = core();
        let mut state = StringifyState::default();
        let mut pending = StringParts::default();
        let mut scratch = 0;
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        for index in 0..INLINE_STRING_PARTS {
            state
                .push_string_part(
                    &mut core,
                    &mut pending,
                    JsString::from(index.to_string()),
                    &mut scratch,
                )
                .unwrap();
        }
        assert_eq!(scratch, 0);
        assert_eq!(state.charged, 0);
        assert_eq!(pending.spill.capacity(), 0);
        for index in (0..INLINE_STRING_PARTS).rev() {
            assert_eq!(pending.pop(), Some(JsString::from(index.to_string())));
            assert!(pending.inline[index].is_none());
        }
        assert_eq!(pending.pop(), None);
        assert!(pending.inline.iter().all(Option::is_none));
        drop(pending);
        release(&mut core, state);
    }

    #[test]
    fn refused_first_spill_preserves_the_complete_inline_prefix() {
        let mut core = core();
        let mut state = StringifyState::default();
        let mut pending = StringParts::default();
        let mut scratch = 0;
        for index in 0..INLINE_STRING_PARTS {
            state
                .push_string_part(
                    &mut core,
                    &mut pending,
                    JsString::from(index.to_string()),
                    &mut scratch,
                )
                .unwrap();
        }
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        assert!(matches!(
            state.push_string_part(&mut core, &mut pending, JsString::from("refused"), &mut scratch),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(scratch, 0);
        assert_eq!(pending.spill.capacity(), 0);
        for index in (0..INLINE_STRING_PARTS).rev() {
            assert_eq!(pending.pop(), Some(JsString::from(index.to_string())));
        }
        assert_eq!(pending.pop(), None);
        drop(pending);
        release(&mut core, state);
    }

    #[test]
    fn mixed_push_pop_order_and_spill_accounting_match_an_ordinary_stack() {
        let mut core = core();
        let mut state = StringifyState::default();
        let mut pending = StringParts::default();
        let mut expected = Vec::new();
        let mut scratch = 0;
        let mut seed = 0x6e9d_a517_u32;
        for index in 0..8192 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if expected.is_empty() || (expected.len() < 128 && seed & 7 < 5) {
                let text = JsString::from(index.to_string());
                state
                    .push_string_part(&mut core, &mut pending, text.clone(), &mut scratch)
                    .unwrap();
                expected.push(text);
            } else {
                assert_eq!(pending.pop(), expected.pop());
            }
            assert_eq!(pending.inline_len + pending.spill.len(), expected.len());
            assert_eq!(
                scratch,
                (pending.spill.capacity() * std::mem::size_of::<JsString>()) as u64
            );
            assert_eq!(state.charged, scratch);
            assert_eq!(core.json_parse_temporary_bytes, scratch);
        }
        let capacity = pending.spill.capacity();
        assert!(capacity != 0);
        let pointer = pending.spill.as_ptr();
        while let Some(value) = expected.pop() {
            assert_eq!(pending.pop(), Some(value));
        }
        // Draining does not uncharge retained capacity. The next fill can
        // reuse it even with no additional admitted heap memory.
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        for _ in 0..INLINE_STRING_PARTS + capacity {
            state
                .push_string_part(&mut core, &mut pending, JsString::from("refill"), &mut scratch)
                .unwrap();
        }
        assert_eq!(pending.spill.as_ptr(), pointer);
        assert_eq!(pending.spill.capacity(), capacity);
        assert!(matches!(
            state.push_string_part(&mut core, &mut pending, JsString::from("overflow"), &mut scratch),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        drop(pending);
        release(&mut core, state);
    }

    #[test]
    fn shallow_quoted_and_raw_ropes_use_only_already_paid_output_capacity() {
        let left = "a".repeat(1024);
        let right = "é😀\n".repeat(80);
        let text = JsString::from(left.clone()).concat(&JsString::from(right.clone()));
        assert!(text.unjoined_concat_children().is_some());
        for quoted in [false, true] {
            let mut core = core();
            let mut state = StringifyState::default();
            for _ in 0..4096 {
                state.push(&mut core, 0x61).unwrap();
            }
            state.output.clear();
            state.projection_bytes = 0;
            let capacity = state.output.capacity();
            let pointer = state.output.as_ptr();
            let charged = state.charged;
            core.config.max_total_memory_bytes = core.estimated_memory_bytes();
            if quoted {
                state.quote(&mut core, &text).unwrap();
            } else {
                state.raw_text(&mut core, &text).unwrap();
            }
            let expected = if quoted {
                format!("\"{}{}\"", left, "é😀\\n".repeat(80))
            } else {
                format!("{left}{right}")
            };
            assert_eq!(state.output, expected.encode_utf16().collect::<Vec<_>>());
            assert_eq!(state.output.as_ptr(), pointer);
            assert_eq!(state.output.capacity(), capacity);
            assert_eq!(state.charged, charged);
            assert!(text.unjoined_concat_children().is_some());
            release(&mut core, state);
        }
    }

    // The previous heap-frontier traversal is the work/output oracle. Its
    // Vec is deliberately unmetered here: these comparisons concern work
    // and string-limit prefixes, with ample memory. Spill admission and
    // memory refusal are tested separately above and below.
    fn reference<const QUOTED: bool>(
        state: &mut StringifyState,
        core: &mut InterpreterCore,
        text: &JsString,
    ) -> Result<(), InterpreterError> {
        let Some([left, right]) = text.unjoined_concat_children() else {
            return state.emit_leaf::<QUOTED>(core, text);
        };
        core.json_charge_work()?;
        let mut pending = vec![right];
        let mut current = left;
        let mut remaining = 256;
        loop {
            if remaining == 0 {
                core.json_charge_work()?;
                remaining = 256;
            }
            remaining -= 1;
            if let Some([left, right]) = current.unjoined_concat_children() {
                pending.push(right);
                current = left;
            } else {
                state.emit_leaf::<QUOTED>(core, &current)?;
                let Some(next) = pending.pop() else {
                    return Ok(());
                };
                current = next;
            }
        }
    }

    fn compare<const QUOTED: bool>(text: &JsString, limit: usize, work: u64) {
        let mut actual_core = core();
        let mut expected_core = core();
        let mut actual = StringifyState::default();
        let mut expected = StringifyState::default();
        for core in [&mut actual_core, &mut expected_core] {
            core.config.max_string_size = limit;
            core.config.instruction_budget = core.instructions_executed + work;
        }
        let got = actual.emit_string::<QUOTED>(&mut actual_core, text);
        let want = reference::<QUOTED>(&mut expected, &mut expected_core, text);
        assert_eq!(got, want);
        assert_eq!(actual.output, expected.output);
        assert_eq!(actual.output.capacity(), expected.output.capacity());
        assert_eq!(actual.projection_bytes, expected.projection_bytes);
        assert_eq!(actual.charged, expected.charged);
        assert_eq!(
            actual_core.instructions_executed,
            expected_core.instructions_executed
        );
        release(&mut actual_core, actual);
        release(&mut expected_core, expected);
    }

    #[test]
    fn frontier_does_not_change_leaf_order_or_work_and_size_refusal_prefixes() {
        let leaf = JsString::from("aé日😀\n".repeat(128));
        for depth in [1, 7, 8, 9, 31, 129] {
            let mut left = leaf.clone();
            let mut right = leaf.clone();
            for _ in 0..depth {
                left = left.concat(&leaf);
                right = leaf.concat(&right);
            }
            for text in [&left, &right] {
                for limit in [0, 1, 63, 64, 255, 256, 2048, 16384] {
                    for work in [0, 1, 2, 4, 64, 100_000] {
                        compare::<false>(text, limit, work);
                        compare::<true>(text, limit, work);
                    }
                }
                assert!(text.unjoined_concat_children().is_some());
            }
        }
    }

    #[test]
    fn spilled_walk_failure_releases_owned_capacity_and_preserves_inherited_scratch() {
        let leaf = JsString::from("a".repeat(1024));
        let mut text = leaf.clone();
        for _ in 0..128 {
            text = text.concat(&leaf);
        }
        for headroom in [0, 64, 127, 128, 255, 512, 1024, 4096] {
            let mut core = core();
            let mut state = StringifyState::default();
            core.json_reserve_temporary(777).unwrap();
            core.config.max_total_memory_bytes = core.estimated_memory_bytes() + headroom;
            assert!(matches!(
                state.raw_text(&mut core, &text),
                Err(InterpreterError::MemoryBudgetExceeded { .. })
            ));
            assert_eq!(state.charged, (state.output.capacity() * 2) as u64);
            assert_eq!(core.json_parse_temporary_bytes, 777 + state.charged);
            assert!(core.pending_exception.is_none());
            core.json_release_temporary(777);
            release(&mut core, state);
            assert!(text.unjoined_concat_children().is_some());
        }
    }

    fn compare_utf8(
        text: &str,
        prefix: &[u16],
        limit: usize,
        work: u64,
        memory: Option<u64>,
        cancel: bool,
    ) {
        let mut actual_core = core();
        let mut expected_core = core();
        let mut actual = StringifyState::default();
        let mut expected = StringifyState::default();
        for &unit in prefix {
            actual.push(&mut actual_core, unit).unwrap();
            expected.push(&mut expected_core, unit).unwrap();
        }
        for core in [&mut actual_core, &mut expected_core] {
            core.config.max_string_size = limit;
            core.config.instruction_budget = core.instructions_executed + work;
            if let Some(bytes) = memory {
                core.config.max_total_memory_bytes = core.estimated_memory_bytes() + bytes;
            }
            if cancel {
                let token = super::super::CancellationToken::new();
                token.cancel();
                core.config.cancellation_token = Some(token);
            }
        }
        let got = actual.quote_utf8(&mut actual_core, text);
        // Keep the previous per-unit codec as an independent oracle, not the
        // new leaf dispatch. This also exercises pair/escape batch boundaries.
        let want = expected.units(&mut expected_core, QuotedUnits::new(text.encode_utf16()));
        assert_eq!(got, want, "text={text:?}, limit={limit}, work={work}");
        assert_eq!(actual.output, expected.output);
        assert_eq!(actual.projection_bytes, expected.projection_bytes);
        assert_eq!(actual.output.capacity(), expected.output.capacity());
        assert_eq!(actual.charged, expected.charged);
        assert_eq!(
            actual_core.instructions_executed,
            expected_core.instructions_executed
        );
        assert_eq!(
            actual_core.json_parse_temporary_bytes,
            expected_core.json_parse_temporary_bytes
        );
        assert!(actual_core.pending_exception.is_none());
        release(&mut actual_core, actual);
        release(&mut expected_core, expected);
    }

    #[test]
    fn utf8_spans_keep_every_escape_and_scalar_at_window_boundaries() {
        for position in [0, 1, 63, 64, 252, 253, 254, 255, 256, 257, 511] {
            for scalar in ['é', '日', '😀', '\u{10ffff}'] {
                let text = format!(
                    "{}{scalar}\"\\\0\x08\x0c\n\r\t\u{2028}\u{2029}{}",
                    "a".repeat(position),
                    "é日😀".repeat(90)
                );
                compare_utf8(&text, &[], 8192, 100_000, None, false);
                for limit in [position, position + 1, position + 3, position + 4, 1024] {
                    compare_utf8(&text, &[0xd800], limit, 100_000, None, false);
                }
            }
        }
        for byte in 0u8..=127 {
            for position in [252, 253, 254, 255, 256] {
                let text = format!("{}😀{}é", "a".repeat(position), char::from(byte));
                compare_utf8(&text, &[], 8192, 100_000, None, false);
            }
        }
    }

    #[test]
    fn utf8_spans_keep_work_memory_and_cancellation_refusal_prefixes() {
        let inputs = [
            format!("é{}😀", "a".repeat(2048)),
            "é日😀\"\\\n\0".repeat(128),
            "😀\u{2028}\u{2029}".repeat(256),
        ];
        for prefix in [vec![], vec![0xd800], vec![0x61; 255], vec![0x61; 256]] {
            for input in &inputs {
                for limit in [0, 1, 2, 3, 63, 64, 65, 255, 256, 257, 511, 4096] {
                    compare_utf8(input, &prefix, limit, 100_000, None, false);
                }
                for work in [0, 1, 2, 8] {
                    compare_utf8(input, &prefix, 16384, work, None, false);
                }
                for bytes in [0, 1, 127, 128, 129, 255, 256, 257, 1024] {
                    compare_utf8(input, &prefix, 16384, 100_000, Some(bytes), false);
                }
                compare_utf8(input, &prefix, 16384, 100_000, None, true);
            }
        }
    }

    #[test]
    fn utf8_spans_need_no_scratch_and_exact_only_leaves_keep_the_old_codec() {
        let inputs = [
            JsString::from(format!("é{}😀", "a".repeat(2048))),
            JsString::from("é日😀\"\\\n".repeat(128)),
            JsString::from_code_units(&[0xd800, 0x22, 0xdc00, 0xd83d, 0xde00]),
        ];
        for input in inputs {
            let mut actual_core = core();
            let mut expected_core = core();
            let mut actual = StringifyState::default();
            let mut expected = StringifyState::default();
            for _ in 0..4096 {
                actual.push(&mut actual_core, 0x61).unwrap();
            }
            actual.output.clear();
            actual.projection_bytes = 0;
            let charged = actual.charged;
            let pointer = actual.output.as_ptr();
            let capacity = actual.output.capacity();
            actual_core.config.max_total_memory_bytes = actual_core.estimated_memory_bytes();
            actual.quote(&mut actual_core, &input).unwrap();
            expected.push(&mut expected_core, 0x22).unwrap();
            expected
                .units(&mut expected_core, QuotedUnits::new(input.encode_utf16()))
                .unwrap();
            expected.push(&mut expected_core, 0x22).unwrap();
            assert_eq!(actual.output, expected.output);
            assert_eq!(actual.projection_bytes, expected.projection_bytes);
            assert_eq!(actual.output.as_ptr(), pointer);
            assert_eq!(actual.output.capacity(), capacity);
            assert_eq!(actual.charged, charged);
            release(&mut actual_core, actual);
            release(&mut expected_core, expected);
        }
    }

    #[test]
    fn utf8_spans_match_the_old_codec_on_shared_and_published_rope_leaves() {
        let leaf = JsString::from(format!("é{}😀\"\\\n", "a".repeat(1024)));
        let mut text = leaf.concat(&leaf);
        for _ in 0..3 {
            text = text.concat(&text);
        }
        for published in [false, true] {
            if published {
                let _ = text.as_str().unwrap();
            }
            let mut actual_core = core();
            let mut expected_core = core();
            let mut actual = StringifyState::default();
            let mut expected = StringifyState::default();
            actual.quote(&mut actual_core, &text).unwrap();
            expected.push(&mut expected_core, 0x22).unwrap();
            expected
                .units(&mut expected_core, QuotedUnits::new(text.encode_utf16()))
                .unwrap();
            expected.push(&mut expected_core, 0x22).unwrap();
            assert_eq!(actual.output, expected.output);
            assert_eq!(actual.projection_bytes, expected.projection_bytes);
            assert_eq!(actual.charged, expected.charged);
            assert_eq!(text.unjoined_concat_children().is_none(), published);
            release(&mut actual_core, actual);
            release(&mut expected_core, expected);
        }
    }

    #[test]
    fn mixed_unicode_builtin_keeps_result_provenance_and_exact_output() {
        use super::super::{Label, RegRange, Value};

        let mut core = core();
        let payload = format!("é{}😀日", "a".repeat(4096));
        core.seed_register(0, Value::str(payload.clone())).unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        let result = core
            .dispatch_builtin_hostcall(
                "builtin:JsonStringify",
                RegRange { start: 0, count: 1 },
                None,
            )
            .unwrap();
        assert_eq!(result, Value::str(format!("\"{payload}\"")));
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
        assert!(core.active_inline_callback_context_label.is_none());
        assert!(core.pending_exception.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}
