//! Fuse mandatory one-character counted loops without per-iteration undo.
//!
//! The compiler's exact CountedLoop/Mark/atom/CounterStep/Jump shape has no
//! choices until its minimum count. Capturing and nullable bodies retain
//! scalar execution. Two register undo frames suffice for this mandatory
//! prefix, including fixed counts; optional greedy/lazy choices still run in
//! the ordinary VM and unwind through these frames and assertion floors.
//! No instruction allowance, capture behavior, or frame width changes.

use super::{BacktrackError, BacktrackRegExp, Frame, Inst, is_line_terminator};

#[derive(Clone, Copy)]
enum Atom {
    Char(char),
    Class(usize),
    Any,
}

pub(super) struct CountedRepeat {
    pub(super) counter: usize,
    pub(super) mark: usize,
    count: usize,
    atom: Atom,
    backward: bool,
}

impl CountedRepeat {
    pub(super) fn at(regexp: &BacktrackRegExp, pc: usize) -> Option<Self> {
        let end = pc.checked_add(5)?;
        let [
            Inst::CountedLoop { counter, min, body, exit, .. },
            Inst::Mark(mark),
            atom,
            Inst::CounterStep { counter: step_counter, mark: step_mark, min: step_min },
            Inst::Jump(head),
        ] = regexp.program.get(pc..end)? else {
            return None;
        };
        if *body != pc + 1
            || *exit != end
            || *head != pc
            || counter != step_counter
            || mark != step_mark
            || min != step_min
            || counter == mark
            || *counter >= regexp.registers
            || *mark >= regexp.registers
            || end >= regexp.program.len()
        {
            return None;
        }
        let (atom, backward) = match atom {
            Inst::Char { c, backward } => {
                let literal = if regexp.ignore_case { regexp.canonicalize(*c) } else { *c };
                (Atom::Char(literal), *backward)
            }
            Inst::Class { class, backward } if *class < regexp.classes.len() => {
                (Atom::Class(*class), *backward)
            }
            Inst::Any { backward } => (Atom::Any, *backward),
            _ => return None,
        };
        Some(Self { counter: *counter, mark: *mark, count: *min, atom, backward })
    }

    fn accepts(&self, regexp: &BacktrackRegExp, chars: &[char], position: usize) -> bool {
        let index = if self.backward { position.checked_sub(1) } else { Some(position) };
        let Some(&c) = index.and_then(|index| chars.get(index)) else {
            return false;
        };
        match self.atom {
            Atom::Char(literal) => {
                if regexp.ignore_case { regexp.canonicalize(c) == literal } else { c == literal }
            }
            Atom::Class(class) => regexp.class_matches(&regexp.classes[class], c),
            Atom::Any => regexp.dot_all || !is_line_terminator(c),
        }
    }

    /// The caller has paid CountedLoop. Each successful iteration pays Mark,
    /// atom, CounterStep, Jump and the next CountedLoop. An atom failure must
    /// undo ALL iterations before the caller takes its surrounding choice.
    /// Budget refusal instead exposes the exact partially written registers.
    pub(super) fn execute_required(
        &self,
        regexp: &BacktrackRegExp,
        chars: &[char],
        mut position: usize,
        registers: &mut [usize],
        steps_left: &mut u64,
    ) -> Result<Option<usize>, BacktrackError> {
        debug_assert!(position <= chars.len());
        let old_count = registers[self.counter];
        let old_mark = registers[self.mark];
        while registers[self.counter] < self.count {
            if *steps_left >= 5 {
                if !self.accepts(regexp, chars, position) {
                    *steps_left -= 2;
                    registers[self.counter] = old_count;
                    registers[self.mark] = old_mark;
                    return Ok(None);
                }
                *steps_left -= 5;
                registers[self.mark] = position;
                position = if self.backward { position - 1 } else { position + 1 };
                registers[self.counter] += 1;
                continue;
            }
            // Reproduce each write boundary rather than rejecting a whole
            // iteration up front: callers observe registers on StepBudget.
            pay(steps_left)?; // Mark
            registers[self.mark] = position;
            pay(steps_left)?; // atom
            if !self.accepts(regexp, chars, position) {
                registers[self.counter] = old_count;
                registers[self.mark] = old_mark;
                return Ok(None);
            }
            pay(steps_left)?; // CounterStep
            registers[self.counter] += 1;
            pay(steps_left)?; // Jump
            pay(steps_left)?; // next CountedLoop (cannot fit this short tail)
            unreachable!("fewer than five steps cannot complete a counted iteration");
        }
        Ok(Some(position))
    }

    pub(super) fn push_undo(&self, stack: &mut Vec<Frame>, old_count: usize, old_mark: usize) {
        if old_count < self.count {
            stack.push(Frame::Register { register: self.mark, old: old_mark });
            stack.push(Frame::Register { register: self.counter, old: old_count });
        }
    }
}

fn pay(steps_left: &mut u64) -> Result<(), BacktrackError> {
    if *steps_left == 0 {
        Err(BacktrackError::StepBudget)
    } else {
        *steps_left -= 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
