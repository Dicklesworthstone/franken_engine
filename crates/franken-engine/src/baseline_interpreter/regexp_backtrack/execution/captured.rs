//! Bounded capture history for greedy and lazy fixed-width repetitions.
//!
//! Recognize nested captures enclosing one consuming atom or a bounded literal
//! block. All selected groups span the entire iteration, so earlier exits can
//! reconstruct their captures from position and width. The original slots and
//! mark are kept once, not once per iteration. Other shapes remain scalar.

use super::{BacktrackError, BacktrackRegExp, Frame, Inst, Run, is_line_terminator};
use super::literals::LiteralBlocks;

const MAX_CAPTURE_GROUPS: usize = 8;
const MAX_CAPTURE_SLOTS: usize = MAX_CAPTURE_GROUPS * 2;

pub(super) struct CapturedRepeat {
    pub(super) exit: usize,
    pub(super) greedy: bool,
    register: usize,
    from: usize,
    to: usize,
    body: usize,
    width: usize,
    backward: bool,
}

impl CapturedRepeat {
    pub(super) fn at(
        regexp: &BacktrackRegExp,
        pc: usize,
        blocks: &mut LiteralBlocks,
    ) -> Option<Self> {
        let Inst::Split { first, second } = regexp.program.get(pc)? else {
            return None;
        };
        let next = pc.checked_add(1)?;
        let greedy = *first == next;
        if !greedy && *second != next {
            return None;
        }
        let target = if greedy { *second } else { *first };
        let repeat = Self::body_at(regexp, pc, target, greedy, blocks)?;
        if !matches!(regexp.program.get(repeat.exit - 2),
            Some(Inst::CheckProgress(mark)) if *mark == repeat.register)
        {
            return None;
        }
        Some(repeat)
    }

    /// Both loop kinds share the exact Mark/Clear/nested-Save/body shape.
    /// The caller separately proves CheckProgress or CounterStep at the tail.
    fn body_at(
        regexp: &BacktrackRegExp,
        pc: usize,
        target: usize,
        greedy: bool,
        blocks: &mut LiteralBlocks,
    ) -> Option<Self> {
        let begin = pc.checked_add(3)?;
        let [Inst::Mark(register), Inst::Clear { from, to }] =
            regexp.program.get(pc + 1..begin)?
        else {
            return None;
        };
        if *register >= regexp.registers || *from < 2
            || from % 2 != 0 || to % 2 != 0 || from >= to
            || *to > regexp.group_count.checked_mul(2)?
        {
            return None;
        }
        let groups = (to - from) / 2;
        if groups > MAX_CAPTURE_GROUPS {
            return None;
        }
        let backward = match regexp.program.get(begin)? {
            Inst::Save(slot) if slot == from => false,
            Inst::Save(slot) if *slot == from + 1 => true,
            _ => return None,
        };
        for group in 0..groups {
            let expected = from + group * 2 + usize::from(backward);
            if !matches!(regexp.program.get(begin + group), Some(Inst::Save(slot)) if *slot == expected) {
                return None;
            }
        }
        let body = begin.checked_add(groups)?;
        let width = match regexp.program.get(body)? {
            Inst::Char { backward: direction, .. } if *direction == backward => {
                if matches!(regexp.program.get(body + 1), Some(Inst::Char { backward: next, .. }) if *next == backward) {
                    blocks.at(regexp, body)?.len
                } else {
                    1
                }
            }
            Inst::Any { backward: direction } if *direction == backward => 1,
            Inst::Class { class, backward: direction }
                if *direction == backward && *class < regexp.classes.len() => 1,
            _ => return None,
        };
        let close = body.checked_add(width)?;
        for group in 0..groups {
            let expected = to - 2 - group * 2 + usize::from(!backward);
            if !matches!(regexp.program.get(close + group), Some(Inst::Save(slot)) if *slot == expected) {
                return None;
            }
        }
        let progress = close.checked_add(groups)?;
        let exit = progress.checked_add(2)?;
        if target != exit || exit >= regexp.program.len()
            || !matches!(regexp.program.get(progress + 1), Some(Inst::Jump(head)) if *head == pc)
        {
            return None;
        }
        Some(Self { exit, greedy, register: *register, from: *from, to: *to, body, width, backward })
    }

    fn previous(&self, position: usize) -> usize {
        if self.backward { position + self.width } else { position - self.width }
    }

    fn restore_iteration(&self, run: &mut Run<'_>, position: usize) {
        let previous = self.previous(position);
        run.registers[self.register] = previous;
        let (from, to) = if self.backward { (position, previous) } else { (previous, position) };
        for pair in run.slots[self.from..self.to].as_chunks_mut::<2>().0 {
            pair[0] = Some(from);
            pair[1] = Some(to);
        }
    }
}

/// A counted loop whose captures all span the complete, positive-width body.
/// Fixed counts need only one original snapshot, irrespective of their size.
pub(super) struct CapturedCounted {
    body: CapturedRepeat,
    counter: usize,
    minimum: usize,
}

impl CapturedCounted {
    pub(super) fn at(
        regexp: &BacktrackRegExp,
        pc: usize,
        blocks: &mut LiteralBlocks,
    ) -> Option<Self> {
        let Inst::CountedLoop { counter, min, max, greedy, body, exit } =
            regexp.program.get(pc)?
        else {
            return None;
        };
        if *max != Some(*min) || *body != pc.checked_add(1)? || *counter >= regexp.registers {
            return None;
        }
        let body = CapturedRepeat::body_at(regexp, pc, *exit, *greedy, blocks)?;
        if *counter == body.register
            || !matches!(regexp.program.get(body.exit - 2),
                Some(Inst::CounterStep { counter: step, mark, min: minimum })
                    if step == counter && *mark == body.register && minimum == min)
        {
            return None;
        }
        Some(Self { body, counter: *counter, minimum: *min })
    }
}

impl Run<'_> {
    /// Execute through the closing Saves, leaving loop-specific bookkeeping
    /// to the caller. A mismatch undoes this iteration; exhaustion leaves the
    /// exact paid writes. Clear's extra slot charge is atomic in both loops.
    fn advance_captured_iteration(
        &mut self,
        repeat: &CapturedRepeat,
        position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let count = repeat.to - repeat.from;
        // Mark, Clear (+ every slot), opening/closing Saves, and the body.
        // The recognized body cannot read captures, branch or call guest code.
        // When all of it is affordable, publish only its final captures: no
        // snapshot, clearing or opening-Save writes are observable in between.
        let complete_cost = 2 + 2 * count + repeat.width;
        if self.steps_left < complete_cost as u64 {
            return self.advance_captured_iteration_precise(repeat, position);
        }
        self.charge(3 + count + count / 2)?; // through the first body instruction
        let next = self.match_captured_atom(repeat, position)?;
        if let Some(next) = next {
            self.charge(count / 2)?; // all closing Saves, now proved affordable
            repeat.restore_iteration(self, next);
        }
        // On mismatch the old state was never touched, exactly as if this
        // iteration's undo records had been unwound. Pay only the failed path.
        Ok(next)
    }

    /// A short allowance needs each individual write/refusal boundary. This
    /// is also the reference for the affordable-body path in focused tests.
    fn advance_captured_iteration_precise(
        &mut self,
        repeat: &CapturedRepeat,
        position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let count = repeat.to - repeat.from;
        let old_mark = self.registers[repeat.register];
        let mut old_slots = [None; MAX_CAPTURE_SLOTS];
        old_slots[..count].copy_from_slice(&self.slots[repeat.from..repeat.to]);
        self.charge(1)?; // Mark
        self.registers[repeat.register] = position;
        self.charge(1)?; // Clear instruction
        self.charge(count)?; // Clear's extra slot work, before any write
        self.slots[repeat.from..repeat.to].fill(None);
        for group in 0..count / 2 {
            self.charge(1)?; // opening Save, outer to inner
            self.slots[repeat.from + group * 2 + usize::from(repeat.backward)] = Some(position);
        }
        self.charge(1)?; // first body instruction
        let Some(next) = self.match_captured_atom(repeat, position)? else {
            self.registers[repeat.register] = old_mark;
            self.slots[repeat.from..repeat.to].copy_from_slice(&old_slots[..count]);
            return Ok(None);
        };
        for group in 0..count / 2 {
            self.charge(1)?; // closing Save, inner to outer
            self.slots[repeat.to - 2 - group * 2 + usize::from(!repeat.backward)] = Some(next);
        }
        Ok(Some(next))
    }

    /// First consuming instruction is already paid by either capture path.
    fn match_captured_atom(
        &mut self,
        repeat: &CapturedRepeat,
        position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let regexp = self.regexp;
        if repeat.width > 1 {
            self.literal_blocks.at(regexp, repeat.body)
                .expect("the immutable bounded literal body was proved")
                .execute_after_dispatch(regexp, &self.input.chars, position, &mut self.steps_left)
        } else {
            Ok(match &regexp.program[repeat.body] {
                Inst::Char { c, backward } => self.step(position, *backward, |input| {
                    if regexp.ignore_case {
                        regexp.canonicalize(input) == regexp.canonicalize(*c)
                    } else { input == *c }
                }),
                Inst::Class { class, backward } => self.class_step(position, *backward, *class),
                Inst::Any { backward } => self.step(position, *backward, |input| {
                    regexp.dot_all || !is_line_terminator(input)
                }),
                _ => unreachable!("a captured body contains only proved consuming atoms"),
            })
        }
    }

    fn advance_captured_body(
        &mut self,
        repeat: &CapturedRepeat,
        position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let Some(next) = self.advance_captured_iteration(repeat, position)? else {
            return Ok(None);
        };
        self.charge(1)?; // CheckProgress: the proved body has positive width
        self.charge(1)?; // Jump
        self.charge(1)?; // next Split
        Ok(Some(next))
    }

    fn advance_captured_counted_body(
        &mut self,
        repeat: &CapturedCounted,
        position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let Some(next) = self.advance_captured_iteration(&repeat.body, position)? else {
            return Ok(None);
        };
        self.charge(1)?; // CounterStep: exactly one completed body
        self.registers[repeat.counter] += 1;
        self.charge(1)?; // Jump
        self.charge(1)?; // next CountedLoop
        Ok(Some(next))
    }

    /// The loop head has been paid. Failure restores the entire mandatory
    /// prefix, not just its last iteration. Refusal leaves partial writes.
    pub(super) fn execute_captured_counted_required(
        &mut self,
        repeat: &CapturedCounted,
        mut position: usize,
        stack: &mut Vec<Frame>,
    ) -> Result<Option<usize>, BacktrackError> {
        let old_count = self.registers[repeat.counter];
        if old_count >= repeat.minimum {
            return Ok(Some(position));
        }
        let body = &repeat.body;
        let old_mark = self.registers[body.register];
        let count = body.to - body.from;
        let mut old_slots = [None; MAX_CAPTURE_SLOTS];
        old_slots[..count].copy_from_slice(&self.slots[body.from..body.to]);
        while self.registers[repeat.counter] < repeat.minimum {
            let Some(next) = self.advance_captured_counted_body(repeat, position)? else {
                self.registers[repeat.counter] = old_count;
                self.registers[body.register] = old_mark;
                self.slots[body.from..body.to].copy_from_slice(&old_slots[..count]);
                return Ok(None);
            };
            position = next;
        }
        stack.push(Frame::Register { register: repeat.counter, old: old_count });
        stack.push(Frame::Register { register: body.register, old: old_mark });
        for (offset, old) in old_slots[..count].iter().copied().enumerate() {
            stack.push(Frame::Slot { slot: body.from + offset, old });
        }
        Ok(Some(position))
    }

    pub(super) fn execute_captured_greedy(
        &mut self,
        repeat: &CapturedRepeat,
        pc: usize,
        mut position: usize,
        stack: &mut Vec<Frame>,
    ) -> Result<usize, BacktrackError> {
        let start = position;
        let old_mark = self.registers[repeat.register];
        let count = repeat.to - repeat.from;
        let mut old_slots = [None; MAX_CAPTURE_SLOTS];
        old_slots[..count].copy_from_slice(&self.slots[repeat.from..repeat.to]);
        while let Some(next) = self.advance_captured_body(repeat, position)? {
            position = next;
        }
        if position != start {
            stack.push(Frame::Register { register: repeat.register, old: old_mark });
            for (offset, old) in old_slots[..count].iter().copied().enumerate() {
                stack.push(Frame::Slot { slot: repeat.from + offset, old });
            }
            stack.push(Frame::CapturedGreedy { pc, position: repeat.previous(position), start });
        }
        Ok(position)
    }

    /// The current lazy exit failed. Defer the original capture/mark history
    /// until this first extension, so a zero-iteration match keeps only its
    /// choice frame. A positive-width body moves monotonically: position can
    /// equal start only before the first completed extension.
    ///
    /// Subsequent failed exits need no individual history. The ordinary
    /// unwinder restores the one original snapshot after body failure; a
    /// budget refusal instead keeps the shared body's exact partial writes.
    pub(super) fn resume_captured_lazy(
        &mut self,
        frame: Frame,
        stack: &mut Vec<Frame>,
    ) -> Result<Option<(usize, usize)>, BacktrackError> {
        let Frame::CapturedLazy { pc, position, start } = frame else {
            unreachable!("only captured lazy choices resume here");
        };
        let repeat = CapturedRepeat::at(self.regexp, pc, &mut self.literal_blocks)
            .expect("the saved capture shape belongs to an immutable program");
        debug_assert!(!repeat.greedy);
        if position == start {
            stack.push(Frame::Register {
                register: repeat.register,
                old: self.registers[repeat.register],
            });
            for slot in repeat.from..repeat.to {
                stack.push(Frame::Slot { slot, old: self.slots[slot] });
            }
        }
        let Some(position) = self.advance_captured_body(&repeat, position)? else {
            return Ok(None);
        };
        stack.push(Frame::CapturedLazy { pc, position, start });
        Ok(Some((repeat.exit, position)))
    }

    pub(super) fn resume_captured_greedy(
        &mut self,
        frame: Frame,
        stack: &mut Vec<Frame>,
    ) -> (usize, usize) {
        let Frame::CapturedGreedy { pc, position, start } = frame else {
            unreachable!("only captured greedy choices resume here");
        };
        let repeat = CapturedRepeat::at(self.regexp, pc, &mut self.literal_blocks)
            .expect("the saved capture shape belongs to an immutable program");
        if position == start {
            // The final alternative is the original zero-extension exit.
            // It may retain a mandatory '+' prefix or an enclosing capture.
            for slot in (repeat.from..repeat.to).rev() {
                let Some(Frame::Slot { slot: saved, old }) = stack.pop() else {
                    unreachable!("captured choices retain their original slots");
                };
                debug_assert_eq!(saved, slot);
                self.slots[slot] = old;
            }
            let Some(Frame::Register { register, old }) = stack.pop() else {
                unreachable!("captured choices retain their original mark");
            };
            debug_assert_eq!(register, repeat.register);
            self.registers[register] = old;
        } else {
            repeat.restore_iteration(self, position);
            stack.push(Frame::CapturedGreedy { pc, position: repeat.previous(position), start });
        }
        (repeat.exit, position)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod counted_tests;

#[cfg(test)]
mod body_tests;
