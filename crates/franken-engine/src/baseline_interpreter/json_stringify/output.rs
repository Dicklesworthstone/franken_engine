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
