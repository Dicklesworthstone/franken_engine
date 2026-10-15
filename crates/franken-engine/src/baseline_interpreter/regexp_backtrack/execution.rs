//! Operation-local backtracking workspace shared by searches and assertions.
//!
//! Each assertion owns a stack suffix. Its success discards internal choices
//! (lookaround is atomic), and its failure cannot consume a caller's choices.
//! Work charges are unchanged; reuse never grants a fresh search allowance.

use super::{BacktrackError, BacktrackRegExp, Captures, Inst, PreparedInput};
use super::{is_line_terminator, is_word_char};

mod literals;
mod prefix;
mod repetitions;

use literals::LiteralBlocks;
use prefix::StartPrefix;
use repetitions::GreedyRepeat;

/// Bound idle capacity between candidate starts and global matches. Large
/// active searches still use the original step bound, then release their peak.
const MAX_RETAINED_FRAMES: usize = 4096;

enum Frame {
    /// Resume at `pc` and `position`.
    Alternative {
        pc: usize,
        position: usize,
    },
    /// A range is paired with the Register frame immediately below it.
    /// Distinct directions keep each payload within the existing frame width.
    RepeatForward {
        pc: usize,
        position: usize,
        start: usize,
    },
    RepeatBackward {
        pc: usize,
        position: usize,
        start: usize,
    },
    Slot {
        slot: usize,
        old: Option<usize>,
    },
    Register {
        register: usize,
        old: usize,
    },
}

pub(super) struct Run<'a> {
    regexp: &'a BacktrackRegExp,
    input: &'a PreparedInput,
    slots: Vec<Option<usize>>,
    registers: Vec<usize>,
    steps_left: u64,
    stack: Vec<Frame>,
    // Allocated once, and only if an assertion actually writes captures.
    // A compaction touches and clears only the slots present in its suffix.
    capture_seen: Vec<bool>,
    literal_blocks: LiteralBlocks,
    #[cfg(test)]
    candidate_executions: usize,
    #[cfg(test)]
    literal_dispatches: usize,
    #[cfg(test)]
    repetitions_disabled: bool,
    #[cfg(test)]
    repeat_dispatches: usize,
}

impl Run<'_> {
    /// Draw `cost` extra steps for an instruction whose work grows with the
    /// pattern or the input (a look-around's capture allowance, a clear over a
    /// slot range, a backreference comparing its capture), so one step stays
    /// bounded work (franken_engine#2 follow-up).
    fn charge(&mut self, cost: usize) -> Result<(), BacktrackError> {
        let cost = u64::try_from(cost).unwrap_or(u64::MAX);
        if self.steps_left < cost {
            self.steps_left = 0;
            return Err(BacktrackError::StepBudget);
        }
        self.steps_left -= cost;
        Ok(())
    }

    /// Run from `pc` at `position` until a `Match`; returns its position.
    /// On failure every slot and register change is undone.
    fn execute(
        &mut self,
        start_pc: usize,
        start_position: usize,
        stack: &mut Vec<Frame>,
    ) -> Result<Option<usize>, BacktrackError> {
        let floor = stack.len();
        let result = self.execute_inner(start_pc, start_position, stack, floor);
        // Match commits captures; failure already undid its local writes.
        // Budget refusal also discards frames, never the caller's prefix.
        stack.truncate(floor);
        result
    }

    fn execute_inner(
        &mut self,
        start_pc: usize,
        start_position: usize,
        stack: &mut Vec<Frame>,
        floor: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let regexp = self.regexp;
        let input = self.input;
        let chars = &input.chars;
        let mut pc = start_pc;
        let mut position = start_position;
        loop {
            if self.steps_left == 0 {
                return Err(BacktrackError::StepBudget);
            }
            self.steps_left -= 1;
            let advanced = match &regexp.program[pc] {
                Inst::Char { c, backward } => {
                    #[cfg(test)]
                    {
                        self.literal_dispatches += 1;
                    }
                    // A one-character atom avoids cache construction. Longer
                    // straight runs use bounded blocks, including lookbehind;
                    // their first instruction was paid by the dispatch above.
                    if matches!(
                        regexp.program.get(pc + 1),
                        Some(Inst::Char { backward: next, .. }) if next == backward
                    ) && let Some(block) = self.literal_blocks.at(regexp, pc)
                    {
                        let advanced = block.execute_after_dispatch(
                            regexp,
                            chars,
                            position,
                            &mut self.steps_left,
                        )?;
                        // Success falls through to the usual pc increment.
                        // Failure ignores this pc and uses the existing undo
                        // stack, including alternatives inside assertions.
                        pc += block.len - 1;
                        advanced
                    } else {
                        self.step(position, *backward, |input| {
                            if regexp.ignore_case {
                                regexp.canonicalize(input) == regexp.canonicalize(*c)
                            } else {
                                input == *c
                            }
                        })
                    }
                }
                Inst::Any { backward } => self.step(position, *backward, |input| {
                    regexp.dot_all || !is_line_terminator(input)
                }),
                Inst::Class { class, backward } => {
                    let class = &regexp.classes[*class];
                    self.step(position, *backward, |input| {
                        regexp.class_matches(class, input)
                    })
                }
                Inst::LineStart => (position == 0
                    || (regexp.multiline && is_line_terminator(chars[position - 1])))
                .then_some(position),
                Inst::LineEnd => (position == chars.len()
                    || (regexp.multiline && is_line_terminator(chars[position])))
                .then_some(position),
                Inst::WordBoundary { negated } => {
                    let before = position > 0 && is_word_char(chars[position - 1]);
                    let after = position < chars.len() && is_word_char(chars[position]);
                    ((before != after) != *negated).then_some(position)
                }
                Inst::Split { first, second } => {
                    let repeat = GreedyRepeat::at(regexp, pc);
                    #[cfg(test)]
                    let repeat = repeat.filter(|_| !self.repetitions_disabled);
                    if let Some(repeat) = repeat {
                        #[cfg(test)]
                        {
                            self.repeat_dispatches += 1;
                        }
                        let old = self.registers[repeat.register];
                        let end = repeat.execute_after_split(
                            regexp,
                            chars,
                            position,
                            &mut self.registers[repeat.register],
                            &mut self.steps_left,
                        )?;
                        repeat.push_choices(stack, position, end, old);
                        position = end;
                        pc = repeat.exit;
                        continue;
                    }
                    stack.push(Frame::Alternative {
                        pc: *second,
                        position,
                    });
                    pc = *first;
                    continue;
                }
                Inst::Jump(target) => {
                    pc = *target;
                    continue;
                }
                Inst::Save(slot) => {
                    stack.push(Frame::Slot {
                        slot: *slot,
                        old: self.slots[*slot],
                    });
                    self.slots[*slot] = Some(position);
                    Some(position)
                }
                Inst::Clear { from, to } => {
                    self.charge(to - from)?;
                    for (offset, value) in self.slots[*from..*to].iter_mut().enumerate() {
                        if let Some(old) = value.take() {
                            stack.push(Frame::Slot {
                                slot: from + offset,
                                old: Some(old),
                            });
                        }
                    }
                    Some(position)
                }
                Inst::Mark(register) => {
                    stack.push(Frame::Register {
                        register: *register,
                        old: self.registers[*register],
                    });
                    self.registers[*register] = position;
                    Some(position)
                }
                Inst::CheckProgress(register) => {
                    (self.registers[*register] != position).then_some(position)
                }
                Inst::CounterReset(counter) => {
                    stack.push(Frame::Register {
                        register: *counter,
                        old: self.registers[*counter],
                    });
                    self.registers[*counter] = 0;
                    Some(position)
                }
                Inst::CountedLoop {
                    counter,
                    min,
                    max,
                    greedy,
                    body,
                    exit,
                } => {
                    let count = self.registers[*counter];
                    if count < *min {
                        pc = *body;
                    } else if max.is_some_and(|max| count >= max) {
                        pc = *exit;
                    } else {
                        let (first, second) = if *greedy {
                            (*body, *exit)
                        } else {
                            (*exit, *body)
                        };
                        stack.push(Frame::Alternative {
                            pc: second,
                            position,
                        });
                        pc = first;
                    }
                    continue;
                }
                Inst::CounterStep { counter, mark, min } => {
                    let count = self.registers[*counter];
                    if count >= *min && self.registers[*mark] == position {
                        None
                    } else {
                        stack.push(Frame::Register {
                            register: *counter,
                            old: count,
                        });
                        self.registers[*counter] = count + 1;
                        Some(position)
                    }
                }
                Inst::BackRef { group, backward } => {
                    // Comparing the captured text costs its length.
                    let captured = match (
                        self.slots.get(group * 2).copied().flatten(),
                        self.slots.get(group * 2 + 1).copied().flatten(),
                    ) {
                        (Some(from), Some(to)) => to.saturating_sub(from),
                        _ => 0,
                    };
                    self.charge(captured)?;
                    self.backreference(*group, position, *backward)
                }
                Inst::Look {
                    negated,
                    body,
                    next,
                } => {
                    // Preserve the original capture allowance and exact
                    // refusal boundary, even though no full snapshot is made.
                    self.charge(self.slots.len())?;
                    let assertion_floor = stack.len();
                    let matched = self
                        .execute_inner(*body, position, stack, assertion_floor)?
                        .is_some();
                    if matched {
                        if *negated {
                            self.discard_assertion_captures(stack, assertion_floor);
                        } else {
                            self.commit_assertion_captures(stack, assertion_floor);
                        }
                    }
                    if matched == *negated {
                        None
                    } else {
                        pc = *next;
                        continue;
                    }
                }
                Inst::Match => return Ok(Some(position)),
            };
            match advanced {
                Some(next_position) => {
                    position = next_position;
                    pc += 1;
                }
                None => loop {
                    if stack.len() == floor {
                        return Ok(None);
                    }
                    match stack.pop() {
                        None => return Ok(None),
                        Some(Frame::Slot { slot, old }) => self.slots[slot] = old,
                        Some(Frame::Register { register, old }) => {
                            self.registers[register] = old;
                        }
                        Some(frame @ (Frame::RepeatForward { .. } | Frame::RepeatBackward { .. })) => {
                            (pc, position) = self.resume_repeat(frame, stack);
                            break;
                        }
                        Some(Frame::Alternative {
                            pc: resume,
                            position: at,
                        }) => {
                            pc = resume;
                            position = at;
                            break;
                        }
                    }
                },
            }
        }
    }

    /// Commit a positive assertion atomically: no internal choice or register
    /// undo may survive, only the pre-assertion value of each changed capture.
    /// Repeated writes retain the FIRST old value in the surviving history.
    /// Internal frames were already charged by their instructions; compacted
    /// capture frames propagated through an enclosing assertion are bounded
    /// by the unchanged per-slot allowance charged at each Look instruction.
    fn commit_assertion_captures(&mut self, stack: &mut Vec<Frame>, floor: usize) {
        let mut write = floor;
        for read in floor..stack.len() {
            let (slot, old) = match &stack[read] {
                Frame::Slot { slot, old } => (*slot, *old),
                _ => continue,
            };
            if self.capture_seen.is_empty() {
                self.capture_seen.resize(self.slots.len(), false);
            }
            if !self.capture_seen[slot] {
                self.capture_seen[slot] = true;
                stack[write] = Frame::Slot { slot, old };
                write += 1;
            }
        }
        // Reset only touched bits, not the full capture array. Remove writes
        // whose final value equals their initial value, as the snapshot did.
        let mut retained = floor;
        for read in floor..write {
            let (slot, old) = match &stack[read] {
                Frame::Slot { slot, old } => (*slot, *old),
                _ => unreachable!("only capture slots survive assertion compaction"),
            };
            self.capture_seen[slot] = false;
            if self.slots[slot] != old {
                stack[retained] = Frame::Slot { slot, old };
                retained += 1;
            }
        }
        stack.truncate(retained);
    }

    /// A matching negative assertion fails without exporting its captures.
    /// Undo its slot history in reverse, never taking an internal alternative.
    /// Its successful sub-run's private repetition registers remain scratch,
    /// just as in the snapshot executor (which restored only capture slots).
    fn discard_assertion_captures(&mut self, stack: &mut Vec<Frame>, floor: usize) {
        while stack.len() > floor {
            if let Some(Frame::Slot { slot, old }) = stack.pop() {
                self.slots[slot] = old;
            }
        }
    }

    /// A mandatory, case-sensitive first character, proved from bytecode,
    /// not source spelling. Save(0) writes only the whole-match start; a
    /// mismatching forward Char immediately undoes it with no other effects.
    fn required_start_literal(&self, sticky: bool) -> Option<char> {
        if sticky || self.regexp.ignore_case {
            return None;
        }
        match self.regexp.program.as_slice() {
            [Inst::Save(0), Inst::Char { c, backward: false }, ..] => Some(*c),
            _ => None,
        }
    }

    /// Skip only fully affordable failed Save(0)/Char attempts. Scanning is
    /// bounded to 256 characters even with unlimited headroom. A remaining
    /// zero/one-step allowance returns to execute, preserving the exact
    /// refusal point and partial capture state rather than fabricating EOF.
    fn skip_literal_misses(&mut self, at: usize, literal: char) -> usize {
        let count = ((self.steps_left / 2).min(256) as usize)
            .min(self.input.chars.len() - at);
        let missed = self.input.chars[at..at + count]
            .iter()
            .position(|&character| character == literal)
            .unwrap_or(count);
        self.steps_left -= 2 * missed as u64;
        missed
    }

    /// Consume one character in the given direction if it satisfies `test`.
    fn step(&self, position: usize, backward: bool, test: impl Fn(char) -> bool) -> Option<usize> {
        if backward {
            (position > 0 && test(self.input.chars[position - 1])).then(|| position - 1)
        } else {
            (position < self.input.chars.len() && test(self.input.chars[position]))
                .then(|| position + 1)
        }
    }

    fn backreference(&self, group: usize, position: usize, backward: bool) -> Option<usize> {
        let (Some(from), Some(to)) = (
            self.slots.get(group * 2).copied().flatten(),
            self.slots.get(group * 2 + 1).copied().flatten(),
        ) else {
            // An unset group matches the empty string.
            return Some(position);
        };
        let length = to.saturating_sub(from);
        let start = if backward {
            position.checked_sub(length)?
        } else {
            if position + length > self.input.chars.len() {
                return None;
            }
            position
        };
        let regexp = self.regexp;
        let same = (0..length).all(|offset| {
            let (expected, actual) = (
                self.input.chars[from + offset],
                self.input.chars[start + offset],
            );
            expected == actual
                || (regexp.ignore_case
                    && regexp.canonicalize(expected) == regexp.canonicalize(actual))
        });
        same.then_some(if backward { start } else { position + length })
    }
}

impl<'a> Run<'a> {
    pub(super) fn new(regexp: &'a BacktrackRegExp, input: &'a PreparedInput, steps_left: u64) -> Self {
        Self {
            regexp,
            input,
            slots: vec![None; regexp.group_count * 2],
            registers: vec![0; regexp.registers],
            steps_left,
            stack: Vec::new(),
            capture_seen: Vec::new(),
            literal_blocks: LiteralBlocks::default(),
            #[cfg(test)]
            candidate_executions: 0,
            #[cfg(test)]
            literal_dispatches: 0,
            #[cfg(test)]
            repetitions_disabled: false,
            #[cfg(test)]
            repeat_dispatches: 0,
        }
    }

    pub(super) fn steps_remaining(&self) -> u64 {
        self.steps_left
    }

    /// Start a fresh search without renewing the operation's work allowance.
    pub(super) fn search(
        &mut self,
        start: usize,
        sticky: bool,
    ) -> Result<Option<Captures>, BacktrackError> {
        self.registers.fill(0);
        // Take ownership only across the mutable run. Nested assertions use
        // disjoint suffixes of this same stack, never a second allocation.
        let mut stack = std::mem::take(&mut self.stack);
        let result = self.search_inner(start, sticky, &mut stack);
        debug_assert!(stack.is_empty());
        self.stack = stack;
        result
    }

    fn search_inner(
        &mut self,
        start: usize,
        sticky: bool,
        stack: &mut Vec<Frame>,
    ) -> Result<Option<Captures>, BacktrackError> {
        let input = self.input;
        let length = input.chars.len();
        let literal = self.required_start_literal(sticky);
        // Keep the existing cheap scan for bare literals. A richer prefix
        // also rejects later mismatches and handles captures/classes/anchors.
        let prefix = (!sticky)
            .then(|| StartPrefix::new(self.regexp))
            .flatten()
            .filter(|prefix| literal.is_none() || prefix.has_multiple_checks());
        let mut at = start;
        if at <= length {
            // A failed execute restores every capture to its entry value.
            // Clear once per search, not once per candidate: the latter
            // costs input_length * capture_count even on immediate misses.
            // Success and budget refusal leave this loop; the next search
            // starts clean, including reuse after a caught budget error.
            self.slots.fill(None);
        }
        while at <= length {
            if let Some(literal) = literal {
                let missed = self.skip_literal_misses(at, literal);
                if missed != 0 {
                    at += missed;
                    continue;
                }
            }
            if let Some(prefix) = &prefix {
                let missed = self.skip_prefix_misses(at, prefix);
                if missed != 0 {
                    at += missed;
                    continue;
                }
            }
            #[cfg(test)]
            {
                self.candidate_executions += 1;
            }
            let matched = self.execute(0, at, stack);
            // Reuse common workspaces, but do not retain an adversarial peak
            // alongside every later global result. The active stack remains
            // bounded by the unchanged instruction-work budget.
            if stack.capacity() > MAX_RETAINED_FRAMES {
                *stack = Vec::new();
            }
            if matched?.is_some() {
                let captures = self
                    .slots
                    .chunks(2)
                    .map(|pair| match (pair[0], pair[1]) {
                        (Some(from), Some(to)) => {
                            Some((input.byte_offset(from), input.byte_offset(to)))
                        }
                        _ => None,
                    })
                    .collect();
                return Ok(Some(captures));
            }
            if sticky {
                break;
            }
            at += 1;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod search_regressions;
