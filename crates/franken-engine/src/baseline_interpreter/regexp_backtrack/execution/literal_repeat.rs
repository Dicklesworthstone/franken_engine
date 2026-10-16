//! Compact greedy and lazy choices for non-capturing, fixed-width literals.
//!
//! Reuse the existing bounded literal blocks, including their case folding,
//! direction and partial-budget semantics. Only the compiler's exact loop
//! shape is accepted. Every earlier exit remains available, at whole-body
//! strides, with the original mark below the range. No new cache or widened
//! backtracking frame is needed; complex and over-wide bodies stay scalar.
//! Lazy continuations try each exit before reading another complete body and
//! retain one original mark, not a per-iteration register-undo chain.

use super::literals::{LiteralBlock, LiteralBlocks};
use super::{BacktrackError, BacktrackRegExp, Frame, Inst, Run};

pub(super) struct LiteralRepeat {
    pub(super) exit: usize,
    pub(super) greedy: bool,
    register: usize,
    body: usize,
    width: usize,
    backward: bool,
}

impl LiteralRepeat {
    pub(super) fn at(
        regexp: &BacktrackRegExp,
        pc: usize,
        blocks: &mut LiteralBlocks,
    ) -> Option<Self> {
        let body = pc.checked_add(2)?;
        let Inst::Split { first, second } = regexp.program.get(pc)? else {
            return None;
        };
        let greedy = *first == pc + 1;
        let target = if greedy { *second } else { *first };
        if (!greedy && *second != pc + 1) || target >= regexp.program.len() {
            return None;
        }
        let Inst::Mark(register) = regexp.program.get(pc + 1)? else {
            return None;
        };
        if *register >= regexp.registers {
            return None;
        }
        let Inst::Char { backward, .. } = regexp.program.get(body)? else {
            return None;
        };
        // The cache's existing cap bounds both recognition and literal work.
        // A block shorter than the body cannot pass the following shape test.
        let width = blocks.at(regexp, body)?.len;
        let end = body.checked_add(width)?;
        let exit = end.checked_add(2)?;
        if target != exit
            || !matches!(regexp.program.get(end), Some(Inst::CheckProgress(mark)) if mark == register)
            || !matches!(regexp.program.get(end + 1), Some(Inst::Jump(head)) if *head == pc)
        {
            return None;
        }
        Some(Self {
            exit,
            greedy,
            register: *register,
            body,
            width,
            backward: *backward,
        })
    }

    /// The preceding whole-body exit, not the preceding character. This is
    /// called only when at least one complete iteration remains to undo.
    fn previous(&self, position: usize) -> usize {
        if self.backward {
            position + self.width
        } else {
            position - self.width
        }
    }

    /// Split was already paid. One iteration pays Mark, each literal, then
    /// CheckProgress, Jump and the next Split. A partial mismatch restores the
    /// pre-iteration mark; a budget error retains the exact last paid write.
    fn advance(
        &self,
        regexp: &BacktrackRegExp,
        chars: &[char],
        block: &LiteralBlock,
        position: usize,
        mark: &mut usize,
        steps_left: &mut u64,
    ) -> Result<Option<usize>, BacktrackError> {
        pay(steps_left)?;
        let old = *mark;
        *mark = position;
        pay(steps_left)?;
        let Some(next) = block.execute_after_dispatch(regexp, chars, position, steps_left)? else {
            *mark = old;
            return Ok(None);
        };
        // A literal block has nonzero width, so CheckProgress always passes.
        // Keep separate payments to preserve each scalar refusal boundary.
        pay(steps_left)?;
        pay(steps_left)?;
        pay(steps_left)?;
        Ok(Some(next))
    }
}

impl Run<'_> {
    pub(super) fn execute_literal_greedy(
        &mut self,
        repeat: &LiteralRepeat,
        pc: usize,
        mut position: usize,
        stack: &mut Vec<Frame>,
    ) -> Result<usize, BacktrackError> {
        let start = position;
        let old = self.registers[repeat.register];
        // Resolve the existing cache once for the entire scan, not per body.
        let block = self.literal_blocks.at(self.regexp, repeat.body)
            .expect("the immutable literal body was proved before execution");
        while let Some(next) = repeat.advance(
            self.regexp,
            &self.input.chars,
            block,
            position,
            &mut self.registers[repeat.register],
            &mut self.steps_left,
        )? {
            position = next;
        }
        if position != start {
            stack.push(Frame::Register { register: repeat.register, old });
            stack.push(Frame::LiteralGreedy {
                pc,
                position: repeat.previous(position),
                start,
            });
        }
        Ok(position)
    }

    /// A lazy loop tries its zero-extension exit immediately. The saved mark
    /// is needed only when every later extension and continuation has failed.
    pub(super) fn push_literal_lazy(
        &mut self,
        repeat: &LiteralRepeat,
        pc: usize,
        position: usize,
        stack: &mut Vec<Frame>,
    ) {
        stack.push(Frame::LiteralLazy {
            pc,
            position,
            old: self.registers[repeat.register],
        });
    }

    /// A failed lazy exit grows by one COMPLETE literal body. Reuse the same
    /// matcher and exact partial-refusal writes as greedy execution. Failure
    /// unwinds all prior marks; a refusal instead leaves the last paid write.
    pub(super) fn resume_literal_lazy(
        &mut self,
        frame: Frame,
        stack: &mut Vec<Frame>,
    ) -> Result<Option<(usize, usize)>, BacktrackError> {
        let Frame::LiteralLazy { pc, position, old } = frame else {
            unreachable!("only a literal lazy continuation resumes here");
        };
        let repeat = LiteralRepeat::at(self.regexp, pc, &mut self.literal_blocks)
            .expect("a saved literal loop belongs to the immutable program");
        let block = self.literal_blocks.at(self.regexp, repeat.body)
            .expect("the immutable literal body was proved before execution");
        let Some(position) = repeat.advance(
            self.regexp,
            &self.input.chars,
            block,
            position,
            &mut self.registers[repeat.register],
            &mut self.steps_left,
        )? else {
            self.registers[repeat.register] = old;
            return Ok(None);
        };
        stack.push(Frame::LiteralLazy { pc, position, old });
        Ok(Some((repeat.exit, position)))
    }

    /// The failing continuation already undid its writes. Restore just the
    /// next whole-body exit. Atomic assertions may discard this range and its
    /// paired register without enumerating any of the earlier choices.
    pub(super) fn resume_literal_greedy(
        &mut self,
        frame: Frame,
        stack: &mut Vec<Frame>,
    ) -> (usize, usize) {
        let Frame::LiteralGreedy { pc, position, start } = frame else {
            unreachable!("only a literal repetition range resumes here");
        };
        let repeat = LiteralRepeat::at(self.regexp, pc, &mut self.literal_blocks)
            .expect("a saved literal loop belongs to the immutable program");
        let Some(Frame::Register { register, old }) = stack.last() else {
            unreachable!("a literal range keeps its original mark immediately below it");
        };
        debug_assert_eq!(*register, repeat.register);
        if position == start {
            self.registers[repeat.register] = *old;
            stack.pop();
        } else {
            let previous = repeat.previous(position);
            self.registers[repeat.register] = previous;
            stack.push(Frame::LiteralGreedy { pc, position: previous, start });
        }
        (repeat.exit, position)
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
