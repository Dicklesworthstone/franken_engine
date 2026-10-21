//! Bounded capture history for greedy repetitions of a fixed-width body.
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
        let begin = pc.checked_add(3)?;
        let [Inst::Split { first, second }, Inst::Mark(register), Inst::Clear { from, to }] =
            regexp.program.get(pc..begin)?
        else {
            return None;
        };
        if *first != pc + 1 || *register >= regexp.registers || *from < 2
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
        if *second != exit || exit >= regexp.program.len()
            || !matches!(regexp.program.get(progress), Some(Inst::CheckProgress(mark)) if mark == register)
            || !matches!(regexp.program.get(progress + 1), Some(Inst::Jump(head)) if *head == pc)
        {
            return None;
        }
        Some(Self { exit, register: *register, from: *from, to: *to, body, width, backward })
    }

    fn previous(&self, position: usize) -> usize {
        if self.backward { position + self.width } else { position - self.width }
    }

    fn restore_iteration(&self, run: &mut Run<'_>, position: usize) {
        let previous = self.previous(position);
        run.registers[self.register] = previous;
        let (from, to) = if self.backward { (position, previous) } else { (previous, position) };
        for pair in run.slots[self.from..self.to].chunks_exact_mut(2) {
            pair[0] = Some(from);
            pair[1] = Some(to);
        }
    }
}

impl Run<'_> {
    /// Split has been paid. Preserve Clear's atomic extra charge and every
    /// Save/Mark write boundary. A mismatch undoes this iteration; exhaustion
    /// leaves exactly the writes completed before the unpaid instruction.
    fn advance_captured_body(
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
        let regexp = self.regexp;
        let next = if repeat.width > 1 {
            self.literal_blocks.at(regexp, repeat.body)
                .expect("the immutable bounded literal body was proved")
                .execute_after_dispatch(regexp, &self.input.chars, position, &mut self.steps_left)?
        } else {
            match &regexp.program[repeat.body] {
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
            }
        };
        let Some(next) = next else {
            self.registers[repeat.register] = old_mark;
            self.slots[repeat.from..repeat.to].copy_from_slice(&old_slots[..count]);
            return Ok(None);
        };
        for group in 0..count / 2 {
            self.charge(1)?; // closing Save, inner to outer
            self.slots[repeat.to - 2 - group * 2 + usize::from(!repeat.backward)] = Some(next);
        }
        self.charge(1)?; // CheckProgress: the proved body has positive width
        self.charge(1)?; // Jump
        self.charge(1)?; // next Split
        Ok(Some(next))
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
