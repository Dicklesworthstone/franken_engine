//! Constant-space execution of counted atoms and fixed-width consuming bodies.
//!
//! Recognize the compiler's exact CountedLoop/Mark/atom/CounterStep/Jump
//! shape. Two register undo frames retain the mandatory prefix. Optional
//! greedy iterations keep every earlier exit in one range paired with two
//! register frames. Lazy iterations retain just the next extension with two
//! original-register undos. Multi-character exits advance by whole bodies,
//! never by characters. Capturing and nullable bodies remain scalar.
//! Assertion floors, partial refusal state and instruction charges are kept;
//! compact choices neither widen ordinary frames nor renew the allowance.

use super::{BacktrackError, BacktrackRegExp, Frame, Inst, Run, is_line_terminator};
use super::literals::LITERAL_WIDTH;
use super::ClassMatches;

#[derive(Clone, Copy)]
enum Atom {
    Char(char),
    Class(usize),
    Any,
    /// First instruction of a complete, bounded literal block.
    Literal(usize),
    /// First instruction of a bounded Char/Class/Any sequence. Its width and
    /// direction are retained by CountedRepeat, not by each saved choice.
    Sequence(usize),
}

pub(super) struct CountedRepeat {
    pub(super) counter: usize,
    pub(super) mark: usize,
    pub(super) width: usize,
    exit: usize,
    count: usize,
    atom: Atom,
    backward: bool,
}

impl CountedRepeat {
    pub(super) fn at(regexp: &BacktrackRegExp, pc: usize) -> Option<Self> {
        let first = pc.checked_add(2)?;
        let [
            Inst::CountedLoop { counter, min, body, exit, .. },
            Inst::Mark(mark),
        ] = regexp.program.get(pc..first)? else {
            return None;
        };
        let end = exit.checked_sub(2)?;
        let width = end.checked_sub(first)?;
        // Validate the COMPLETE body. The same existing width bound applies
        // to literal blocks and mixed consuming sequences; no truncated
        // prefix can stand in for the loop's body.
        if width == 0 || width > LITERAL_WIDTH || *exit >= regexp.program.len() {
            return None;
        }
        let [
            Inst::CounterStep { counter: step_counter, mark: step_mark, min: step_min },
            Inst::Jump(head),
        ] = regexp.program.get(end..*exit)? else {
            return None;
        };
        if *body != pc + 1
            || *head != pc
            || counter != step_counter
            || mark != step_mark
            || min != step_min
            || counter == mark
            || *counter >= regexp.registers
            || *mark >= regexp.registers
        {
            return None;
        }
        let (atom, backward) = match regexp.program.get(first)? {
            Inst::Char { backward, .. } if width > 1 => {
                if regexp.program[first..end].iter().all(|instruction| {
                    matches!(instruction, Inst::Char { backward: direction, .. }
                        if direction == backward)
                }) {
                    // Keep literal recognition and its existing cache fast.
                    (Atom::Literal(first), *backward)
                } else {
                    let backward = fixed_body_direction(regexp, first, width)?;
                    (Atom::Sequence(first), backward)
                }
            }
            Inst::Class { .. } | Inst::Any { .. } if width > 1 => {
                let backward = fixed_body_direction(regexp, first, width)?;
                (Atom::Sequence(first), backward)
            }
            Inst::Char { c, backward } => {
                let literal = if regexp.ignore_case { regexp.canonicalize(*c) } else { *c };
                (Atom::Char(literal), *backward)
            }
            Inst::Class { class, backward } if width == 1 && *class < regexp.classes.len() => {
                (Atom::Class(*class), *backward)
            }
            Inst::Any { backward } if width == 1 => (Atom::Any, *backward),
            _ => return None,
        };
        Some(Self { counter: *counter, mark: *mark, width, exit: *exit, count: *min, atom, backward })
    }

    /// Reconstruct the preceding COMPLETE iteration, in either direction.
    /// A saved range always has at least one successful body to undo here.
    fn previous(&self, position: usize) -> usize {
        if self.backward { position + self.width } else { position - self.width }
    }

    fn accepts(
        &self,
        regexp: &BacktrackRegExp,
        chars: &[char],
        position: usize,
        classes: &mut ClassMatches,
    ) -> bool {
        let index = if self.backward { position.checked_sub(1) } else { Some(position) };
        let Some(&c) = index.and_then(|index| chars.get(index)) else {
            return false;
        };
        match self.atom {
            Atom::Char(literal) => {
                if regexp.ignore_case { regexp.canonicalize(c) == literal } else { c == literal }
            }
            Atom::Class(class) => classes.matches(regexp, class, c),
            Atom::Any => regexp.dot_all || !is_line_terminator(c),
            Atom::Literal(_) | Atom::Sequence(_) => {
                unreachable!("multi-character bodies use their whole-body matcher")
            }
        }
    }

    pub(super) fn push_undo(&self, stack: &mut Vec<Frame>, old_count: usize, old_mark: usize) {
        if old_count < self.count {
            stack.push(Frame::Register { register: self.mark, old: old_mark });
            stack.push(Frame::Register { register: self.counter, old: old_count });
        }
    }
}

impl Run<'_> {
    /// Required and optional bodies share one executor. A failed mandatory
    /// body undoes the entire prefix; refusal retains its last paid writes.
    pub(super) fn execute_counted_required(
        &mut self,
        repeat: &CountedRepeat,
        mut position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let old_count = self.registers[repeat.counter];
        let old_mark = self.registers[repeat.mark];
        while self.registers[repeat.counter] < repeat.count {
            let Some(next) = self.advance_counted_atom(repeat, position)? else {
                self.registers[repeat.counter] = old_count;
                self.registers[repeat.mark] = old_mark;
                return Ok(None);
            };
            position = next;
        }
        Ok(Some(position))
    }

    /// Execute one complete body and pay through the following CountedLoop.
    /// A failed atom undoes its Mark; budget refusal keeps precisely the
    /// writes that scalar dispatch completed before the unpaid instruction.
    fn advance_counted_atom(
        &mut self,
        repeat: &CountedRepeat,
        position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        debug_assert!(position <= self.input.chars.len());
        if let Atom::Literal(body) | Atom::Sequence(body) = repeat.atom {
            pay(&mut self.steps_left)?; // Mark
            let old_mark = self.registers[repeat.mark];
            self.registers[repeat.mark] = position;
            pay(&mut self.steps_left)?; // First consuming instruction
            let next = match repeat.atom {
                Atom::Literal(_) => {
                    let block = self.literal_blocks.at(self.regexp, body)
                        .expect("a complete bounded literal body was proved before execution");
                    debug_assert_eq!(block.len, repeat.width);
                    block.execute_after_dispatch(
                        self.regexp, &self.input.chars, position, &mut self.steps_left,
                    )?
                }
                Atom::Sequence(_) => execute_fixed_body_after_dispatch(
                    self.regexp, body..body + repeat.width, repeat.backward,
                    &self.input.chars, position, &mut self.steps_left, &mut self.class_matches,
                )?,
                _ => unreachable!("only a multi-character body enters this path"),
            };
            let Some(next) = next else {
                self.registers[repeat.mark] = old_mark;
                return Ok(None);
            };
            // Increment once per complete body, never once per character.
            pay(&mut self.steps_left)?; // CounterStep
            self.registers[repeat.counter] += 1;
            pay(&mut self.steps_left)?; // Jump
            pay(&mut self.steps_left)?; // Next CountedLoop
            return Ok(Some(next));
        }
        if self.steps_left >= 5 {
            if !repeat.accepts(self.regexp, &self.input.chars, position, &mut self.class_matches) {
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
        if !repeat.accepts(self.regexp, &self.input.chars, position, &mut self.class_matches) {
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
                position: repeat.previous(position),
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
        Ok(Some((repeat.exit, position)))
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
        let distance = position.abs_diff(start);
        debug_assert_eq!(distance % repeat.width, 0);
        // Counters count iterations, not matched characters. Preserve the
        // existing one-atom path without introducing division there.
        let iterations = if repeat.width == 1 { distance } else { distance / repeat.width };
        self.registers[repeat.counter] = old_count + iterations;
        if position == start {
            self.registers[repeat.mark] = old_mark;
            stack.truncate(paired);
        } else {
            let previous = repeat.previous(position);
            self.registers[repeat.mark] = previous;
            stack.push(Frame::CountedGreedy { pc, position: previous, start });
        }
        (repeat.exit, position)
    }
}

/// Prove a whole fixed-width body of consuming atoms. Captures, assertions,
/// alternatives, nullable instructions and mixed directions remain scalar.
/// Recognition is bounded by the existing literal width, with no new cache.
pub(super) fn fixed_body_direction(
    regexp: &BacktrackRegExp,
    first: usize,
    width: usize,
) -> Option<bool> {
    if !(2..=LITERAL_WIDTH).contains(&width) {
        return None;
    }
    let instructions = regexp.program.get(first..first.checked_add(width)?)?;
    let direction = |instruction: &Inst| match instruction {
        Inst::Char { backward, .. } | Inst::Any { backward } => Some(*backward),
        Inst::Class { class, backward } if *class < regexp.classes.len() => Some(*backward),
        _ => None,
    };
    let backward = direction(instructions.first()?)?;
    instructions.iter().all(|instruction| direction(instruction) == Some(backward))
        .then_some(backward)
}

/// Match the already-proved mixed body in instruction order. Only its first
/// instruction is prepaid. Each remaining instruction is paid BEFORE reading
/// input, even at EOF; failure and refusal therefore retain scalar boundaries.
/// Reuse the Run's existing class predicate cache; do not add another cache.
/// This routine owns no register/capture writes or choice frames.
/// The enclosing loop owns its Mark and all rollback/publication decisions.
pub(super) fn execute_fixed_body_after_dispatch(
    regexp: &BacktrackRegExp,
    body: std::ops::Range<usize>,
    backward: bool,
    chars: &[char],
    mut position: usize,
    steps_left: &mut u64,
    classes: &mut ClassMatches,
) -> Result<Option<usize>, BacktrackError> {
    debug_assert!(position <= chars.len());
    debug_assert!((2..=LITERAL_WIDTH).contains(&body.len()));
    for (offset, instruction) in regexp.program[body].iter().enumerate() {
        if offset != 0 {
            pay(steps_left)?;
        }
        let index = if backward { position.checked_sub(1) } else { Some(position) };
        let Some(&input) = index.and_then(|index| chars.get(index)) else {
            return Ok(None);
        };
        let accepts = match instruction {
            Inst::Char { c, .. } => {
                if regexp.ignore_case {
                    regexp.canonicalize(input) == regexp.canonicalize(*c)
                } else {
                    input == *c
                }
            }
            Inst::Class { class, .. } => classes.matches(regexp, *class, input),
            Inst::Any { .. } => regexp.dot_all || !is_line_terminator(input),
            _ => unreachable!("the complete fixed-width body was proved before execution"),
        };
        if !accepts {
            return Ok(None);
        }
        position = if backward { position - 1 } else { position + 1 };
    }
    Ok(Some(position))
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

#[cfg(test)]
mod literal_tests;

#[cfg(test)]
mod mixed_tests;
