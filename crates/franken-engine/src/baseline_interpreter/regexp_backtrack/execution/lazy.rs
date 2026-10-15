//! Constant-space continuations for capture-free, one-character lazy loops.
//!
//! A lazy exit is tried BEFORE its next atom. Once that exit fails, it is
//! never needed again, so all prior Mark undo records can be represented by
//! the original mark in a single continuation. No input is scanned eagerly.
//! Capturing, nullable and branching bodies retain ordinary execution.

use super::{BacktrackError, BacktrackRegExp, Frame, Inst, Run, is_line_terminator};

pub(super) struct LazyRepeat {
    pub(super) register: usize,
    pub(super) exit: usize,
}

impl LazyRepeat {
    /// Recognize only the compiler's exact lazy Split/Mark/atom/progress/Jump.
    /// The saved pc refers to immutable bytecode, not to a second compiled plan.
    pub(super) fn at(regexp: &BacktrackRegExp, pc: usize) -> Option<Self> {
        let exit = pc.checked_add(5)?;
        let [
            Inst::Split { first, second },
            Inst::Mark(register),
            atom,
            Inst::CheckProgress(progress),
            Inst::Jump(head),
        ] = regexp.program.get(pc..exit)? else {
            return None;
        };
        if *first != exit
            || *second != pc + 1
            || *head != pc
            || register != progress
            || *register >= regexp.registers
            || exit >= regexp.program.len()
        {
            return None;
        }
        match atom {
            Inst::Char { .. } | Inst::Any { .. } => {}
            Inst::Class { class, .. } if *class < regexp.classes.len() => {}
            _ => return None,
        }
        Some(Self {
            register: *register,
            exit,
        })
    }
}

impl Run<'_> {
    /// The previous exit and all of its choices have failed. Execute exactly
    /// one more atom, paying Mark/atom/progress/Jump/next Split, then try the
    /// next exit. A failed atom restores ALL prior marks in constant space;
    /// a budget refusal retains the exact partially written mark instead.
    pub(super) fn resume_lazy_repeat(
        &mut self,
        frame: Frame,
        stack: &mut Vec<Frame>,
    ) -> Result<Option<(usize, usize)>, BacktrackError> {
        let Frame::LazyRepeat { pc, position, old } = frame else {
            unreachable!("only a lazy continuation resumes here");
        };
        let repeat = LazyRepeat::at(self.regexp, pc)
            .expect("the immutable lazy loop was proved before saving its continuation");
        let next = if self.steps_left >= 5 {
            let next = self.lazy_atom_step(pc, position);
            if next.is_none() {
                self.steps_left -= 2; // Mark and failing atom; unwind is free.
                self.registers[repeat.register] = old;
                return Ok(None);
            }
            self.steps_left -= 5;
            self.registers[repeat.register] = position;
            next
        } else {
            self.charge(1)?; // Mark
            self.registers[repeat.register] = position;
            self.charge(1)?; // atom
            let next = self.lazy_atom_step(pc, position);
            if next.is_none() {
                self.registers[repeat.register] = old;
                return Ok(None);
            }
            // A proved atom always consumes one character, so progress cannot
            // fail. Charge individually, preserving refusal after a paid atom.
            self.charge(1)?; // CheckProgress
            self.charge(1)?; // Jump
            self.charge(1)?; // next Split
            next
        };
        let position = next.expect("a failed lazy atom returned before saving a continuation");
        stack.push(Frame::LazyRepeat { pc, position, old });
        Ok(Some((repeat.exit, position)))
    }

    fn lazy_atom_step(&self, pc: usize, position: usize) -> Option<usize> {
        let regexp = self.regexp;
        match &regexp.program[pc + 2] {
            Inst::Char { c, backward } => self.step(position, *backward, |input| {
                if regexp.ignore_case {
                    regexp.canonicalize(input) == regexp.canonicalize(*c)
                } else {
                    input == *c
                }
            }),
            Inst::Class { class, backward } => self.step(position, *backward, |input| {
                regexp.class_matches(&regexp.classes[*class], input)
            }),
            Inst::Any { backward } => self.step(position, *backward, |input| {
                regexp.dot_all || !is_line_terminator(input)
            }),
            _ => unreachable!("lazy continuations contain exactly one consuming atom"),
        }
    }
}

#[cfg(test)]
mod tests;
