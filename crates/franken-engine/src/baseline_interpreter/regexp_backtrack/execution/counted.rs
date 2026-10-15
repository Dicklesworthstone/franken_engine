//! Constant-space execution of one-character counted repetitions.
//!
//! Recognize the compiler's exact CountedLoop/Mark/atom/CounterStep/Jump
//! shape. Two register undo frames retain the mandatory prefix. Optional
//! greedy iterations keep every earlier exit in one range paired with two
//! register frames. Lazy iterations retain just the next extension with two
//! original-register undos. Capturing and nullable bodies remain scalar.
//! Assertion floors, partial refusal state and instruction charges are kept;
//! compact choices neither widen ordinary frames nor renew the allowance.

use super::{BacktrackError, BacktrackRegExp, Frame, Inst, Run, is_line_terminator};

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

impl Run<'_> {
    /// Execute one optional atom and pay through the following CountedLoop.
    /// A failed atom undoes its Mark; budget refusal keeps precisely the
    /// writes that scalar dispatch completed before the unpaid instruction.
    fn advance_counted_atom(
        &mut self,
        repeat: &CountedRepeat,
        position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        debug_assert!(position <= self.input.chars.len());
        if self.steps_left >= 5 {
            if !repeat.accepts(self.regexp, &self.input.chars, position) {
                self.steps_left -= 2; // Mark and the failed atom.
                return Ok(None);
            }
            self.steps_left -= 5;
            self.registers[repeat.mark] = position;
            self.registers[repeat.counter] += 1;
            return Ok(Some(if repeat.backward { position - 1 } else { position + 1 }));
        }
        let old_mark = self.registers[repeat.mark];
        pay(&mut self.steps_left)?;
        self.registers[repeat.mark] = position;
        pay(&mut self.steps_left)?;
        if !repeat.accepts(self.regexp, &self.input.chars, position) {
            self.registers[repeat.mark] = old_mark;
            return Ok(None);
        }
        pay(&mut self.steps_left)?;
        self.registers[repeat.counter] += 1;
        pay(&mut self.steps_left)?;
        pay(&mut self.steps_left)?;
        unreachable!("fewer than five steps cannot complete a counted iteration");
    }

    /// CountedLoop was paid and its minimum satisfied. Scan to the maximum
    /// or first nonmatching atom. No body capture, alternative or assertion
    /// exists in this proved shape, but EVERY earlier optional exit must be
    /// kept for a failing continuation. A failing first atom adds no history.
    pub(super) fn execute_counted_greedy(
        &mut self,
        repeat: &CountedRepeat,
        pc: usize,
        mut position: usize,
        maximum: Option<usize>,
        stack: &mut Vec<Frame>,
    ) -> Result<usize, BacktrackError> {
        let start = position;
        let old_count = self.registers[repeat.counter];
        let old_mark = self.registers[repeat.mark];
        debug_assert!(old_count >= repeat.count);
        while maximum.is_none_or(|maximum| self.registers[repeat.counter] < maximum) {
            let Some(next) = self.advance_counted_atom(repeat, position)? else {
                break;
            };
            position = next;
        }
        if position != start {
            stack.push(Frame::Register { register: repeat.mark, old: old_mark });
            stack.push(Frame::Register { register: repeat.counter, old: old_count });
            stack.push(Frame::CountedGreedy {
                pc,
                position: if repeat.backward { position + 1 } else { position - 1 },
                start,
            });
        }
        Ok(position)
    }

    /// CountedLoop was paid, its minimum satisfied and maximum not reached.
    /// Keep only the next extension: all earlier lazy exits have already
    /// failed. The two undos summarize the entire optional prefix, separate
    /// from the required prefix's existing history. No atom executes yet.
    pub(super) fn push_counted_lazy(
        &self,
        repeat: &CountedRepeat,
        pc: usize,
        position: usize,
        stack: &mut Vec<Frame>,
    ) {
        stack.push(Frame::Register {
            register: repeat.mark,
            old: self.registers[repeat.mark],
        });
        stack.push(Frame::Register {
            register: repeat.counter,
            old: self.registers[repeat.counter],
        });
        stack.push(Frame::CountedLazy { pc, position });
    }

    /// Grow a failed lazy exit by one atom with the same helper as the greedy
    /// path. Failure leaves paired undos for ordinary unwinding; refusal keeps
    /// partial writes. At the maximum, remove only the extension choice: the
    /// original registers must still be restored if that final exit fails.
    pub(super) fn resume_counted_lazy(
        &mut self,
        frame: Frame,
        stack: &mut Vec<Frame>,
    ) -> Result<Option<(usize, usize)>, BacktrackError> {
        let Frame::CountedLazy { pc, position } = frame else {
            unreachable!("only a counted lazy continuation resumes here");
        };
        let repeat = CountedRepeat::at(self.regexp, pc)
            .expect("the immutable counted loop was proved before saving its continuation");
        let Some(position) = self.advance_counted_atom(&repeat, position)? else {
            return Ok(None);
        };
        let Inst::CountedLoop { max, greedy: false, .. } = &self.regexp.program[pc] else {
            unreachable!("a counted lazy continuation belongs to a lazy loop");
        };
        if max.is_none_or(|maximum| self.registers[repeat.counter] < maximum) {
            stack.push(Frame::CountedLazy { pc, position });
        }
        Ok(Some((pc + 5, position)))
    }

    /// Tail writes have already unwound when this range is popped. Rebuild
    /// exactly one earlier exit and its counter/mark state; do not reexecute
    /// an atom or charge another loop head. The last exit consumes both
    /// paired registers, leaving any mandatory-prefix undo below them.
    pub(super) fn resume_counted_greedy(
        &mut self,
        frame: Frame,
        stack: &mut Vec<Frame>,
    ) -> (usize, usize) {
        let Frame::CountedGreedy { pc, position, start } = frame else {
            unreachable!("only a counted greedy range resumes here");
        };
        let repeat = CountedRepeat::at(self.regexp, pc)
            .expect("the immutable counted loop was proved before saving its range");
        let paired = stack.len().checked_sub(2).expect("two paired register frames");
        let (old_mark, old_count) = match (&stack[paired], &stack[paired + 1]) {
            (Frame::Register { register: mark, old: old_mark },
             Frame::Register { register: counter, old: old_count })
                if *mark == repeat.mark && *counter == repeat.counter => (*old_mark, *old_count),
            _ => unreachable!("counted choices retain their mark and counter undo"),
        };
        self.registers[repeat.counter] = old_count + position.abs_diff(start);
        if position == start {
            self.registers[repeat.mark] = old_mark;
            stack.truncate(paired);
        } else {
            let previous = if repeat.backward { position + 1 } else { position - 1 };
            self.registers[repeat.mark] = previous;
            stack.push(Frame::CountedGreedy { pc, position: previous, start });
        }
        (pc + 5, position)
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

#[cfg(test)]
mod optional_tests;

#[cfg(test)]
mod lazy_tests;
