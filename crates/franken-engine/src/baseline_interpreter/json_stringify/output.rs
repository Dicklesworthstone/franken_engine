//! Bounded UTF-16 output and allocation-free JSON escaping.
//!
//! A batch may use only slots already admitted by the scalar writer and may
//! not cross the next work checkpoint. Three projected bytes per code unit
//! is a safe upper bound even for lone surrogates; a healed pair needs four
//! bytes across its two units. Near a limit, the scalar writer still decides
//! the precise failing unit and preserves the partially written prefix.

use std::iter::{Fuse, FusedIterator, Peekable};

use super::{InterpreterCore, InterpreterError, StringifyState};

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
            self.units(core, QuotedUnits::new(text.encode_utf16()))
        } else {
            self.units(core, text.encode_utf16())
        }
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
        let mut pending = Vec::new();
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
        pending: &mut Vec<super::JsString>,
        part: super::JsString,
        scratch: &mut u64,
    ) -> Result<(), InterpreterError> {
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
