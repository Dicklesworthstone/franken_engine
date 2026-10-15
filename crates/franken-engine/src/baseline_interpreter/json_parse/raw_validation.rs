//! Validate JSON.rawJSON primitives without building a discarded parsed value.
//!
//! The scanner retains only lexical state. Rope leaves share their immutable
//! backing and use a fallible, admission-accounted frontier; flat and exact
//! strings need no heap scratch. A miss returns to the existing JSON parser
//! for its diagnostic, never accepts a grammar extension. No guest callback
//! runs between coercion and validation.

use super::*;

#[derive(Clone, Copy, Default)]
enum RawState {
    #[default]
    Start,
    Minus,
    Zero,
    Integer,
    FractionStart,
    Fraction,
    ExponentStart,
    ExponentSign,
    Exponent,
    String,
    Escape,
    Hex(u8),
    Literal(&'static [u8], usize),
    Done,
    Rejected,
}

#[derive(Default)]
struct RawScanner {
    state: RawState,
}

impl RawScanner {
    /// Consume one exact UTF-16 unit, including literal lone surrogates.
    /// JSON escapes are ASCII; a surrogate has no lexical role in this grammar.
    fn feed(&mut self, unit: u16) -> bool {
        use RawState::*;

        self.state = match self.state {
            Start => match unit {
                0x22 => String,
                0x2d => Minus,
                0x30 => Zero,
                0x31..=0x39 => Integer,
                0x74 => Literal(b"rue", 0),
                0x66 => Literal(b"alse", 0),
                0x6e => Literal(b"ull", 0),
                _ => Rejected,
            },
            Minus => match unit {
                0x30 => Zero,
                0x31..=0x39 => Integer,
                _ => Rejected,
            },
            Zero => match unit {
                0x2e => FractionStart,
                0x45 | 0x65 => ExponentStart,
                _ => Rejected,
            },
            Integer => match unit {
                0x30..=0x39 => Integer,
                0x2e => FractionStart,
                0x45 | 0x65 => ExponentStart,
                _ => Rejected,
            },
            FractionStart => match unit {
                0x30..=0x39 => Fraction,
                _ => Rejected,
            },
            Fraction => match unit {
                0x30..=0x39 => Fraction,
                0x45 | 0x65 => ExponentStart,
                _ => Rejected,
            },
            ExponentStart => match unit {
                0x2b | 0x2d => ExponentSign,
                0x30..=0x39 => Exponent,
                _ => Rejected,
            },
            ExponentSign | Exponent => match unit {
                0x30..=0x39 => Exponent,
                _ => Rejected,
            },
            String => match unit {
                0x22 => Done,
                0x5c => Escape,
                0x00..=0x1f => Rejected,
                _ => String,
            },
            Escape => match unit {
                0x22 | 0x2f | 0x5c | 0x62 | 0x66 | 0x6e | 0x72 | 0x74 => String,
                0x75 => Hex(4),
                _ => Rejected,
            },
            Hex(remaining) => match unit {
                0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66 => {
                    if remaining == 1 {
                        String
                    } else {
                        Hex(remaining - 1)
                    }
                }
                _ => Rejected,
            },
            Literal(tail, offset) => {
                if tail.get(offset).is_some_and(|&byte| u16::from(byte) == unit) {
                    if offset + 1 == tail.len() {
                        Done
                    } else {
                        Literal(tail, offset + 1)
                    }
                } else {
                    Rejected
                }
            }
            Done | Rejected => Rejected,
        };
        !matches!(self.state, Rejected)
    }

    fn complete(&self) -> bool {
        matches!(
            self.state,
            RawState::Zero
                | RawState::Integer
                | RawState::Fraction
                | RawState::Exponent
                | RawState::Done
        )
    }
}

#[derive(Default)]
struct ValidationWork {
    remaining: usize,
}

impl ValidationWork {
    /// Bound both lexical work and a deep rope spine before its first unit.
    /// Do not reset the interval at leaf boundaries or let empty leaves avoid it.
    fn tick(&mut self, core: &mut InterpreterCore) -> Result<(), InterpreterError> {
        if self.remaining == 0 {
            core.json_charge_work()?;
            self.remaining = 256;
        }
        self.remaining -= 1;
        Ok(())
    }
}

fn push_pending(
    core: &mut InterpreterCore,
    pending: &mut Vec<JsString>,
    part: JsString,
    charged: &mut u64,
) -> Result<(), InterpreterError> {
    if pending.len() == pending.capacity() {
        let previous = pending.capacity();
        let additional = previous.max(4);
        let slot = std::mem::size_of::<JsString>() as u64;
        let error = || core.memory_budget_error(u64::MAX, core.heap_object_count_u32());
        let growth = u64::try_from(additional)
            .ok()
            .and_then(|count| count.checked_mul(slot))
            .ok_or_else(error)?;
        core.json_reserve_temporary(growth)?;
        *charged += growth;
        pending.try_reserve_exact(additional).map_err(|_| {
            core.memory_budget_error(u64::MAX, core.heap_object_count_u32())
        })?;
        let retained = u64::try_from(pending.capacity() - previous)
            .ok()
            .and_then(|count| count.checked_mul(slot))
            .ok_or_else(|| core.memory_budget_error(u64::MAX, core.heap_object_count_u32()))?;
        if retained > growth {
            core.json_reserve_temporary(retained - growth)?;
            *charged += retained - growth;
        }
    }
    pending.push(part);
    Ok(())
}

impl InterpreterCore {
    pub(super) fn json_raw_text_is_valid(
        &mut self,
        text: &JsString,
    ) -> Result<bool, InterpreterError> {
        let mut scanner = RawScanner::default();
        let mut work = ValidationWork::default();
        let mut pending = Vec::new();
        let mut charged = 0;
        let mut part = text.clone();
        let outcome = (|| {
            loop {
                work.tick(self)?;
                if let Some([left, right]) = part.unjoined_concat_children() {
                    push_pending(self, &mut pending, right, &mut charged)?;
                    part = left;
                    continue;
                }
                // None proves flat/exact storage or a published flat buffer.
                // Publication is one-way. This iterator cannot allocate an
                // unaccounted rope cursor or start an eager flattening.
                for unit in part.encode_utf16() {
                    work.tick(self)?;
                    if !scanner.feed(unit) {
                        return Ok(false);
                    }
                }
                match pending.pop() {
                    Some(next) => part = next,
                    None => return Ok(scanner.complete()),
                }
            }
        })();
        drop(part);
        drop(pending);
        self.json_release_temporary(charged);
        outcome
    }
}

#[cfg(test)]
mod tests;
