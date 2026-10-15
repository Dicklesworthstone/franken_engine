//! Exact rejection of impossible starts before entering the backtracking VM.
//!
//! Straight prefixes use precomputed checks. Alternatives and optional prefixes
//! use a bounded, read-only walk in the VM's choice order. Only a completely
//! failed candidate can be skipped: its capture/register writes would all be
//! undone. Successful, unsupported, over-complex and unaffordable candidates
//! still execute normally, including their exact partial refusal state.

use super::{BacktrackRegExp, Inst, Run, is_line_terminator, is_word_char};

const MAX_PREFIX_INSTRUCTIONS: usize = 64;
const MAX_PREFIX_CHECKS: usize = 8;
const MAX_PREFIX_ALTERNATIVES: usize = 8;
const MAX_SKIP_BATCH: usize = 256;

#[derive(Clone, Copy)]
enum Predicate {
    Char(char),
    Class(usize),
    Any,
    LineStart,
    LineEnd,
    WordBoundary(bool),
}

impl Predicate {
    fn accepts(self, regexp: &BacktrackRegExp, chars: &[char], position: usize) -> bool {
        debug_assert!(position <= chars.len());
        match self {
            Self::Char(literal) => chars.get(position).is_some_and(|&c| {
                if regexp.ignore_case {
                    regexp.canonicalize(c) == literal
                } else {
                    c == literal
                }
            }),
            Self::Class(class) => chars
                .get(position)
                .is_some_and(|&c| regexp.class_matches(&regexp.classes[class], c)),
            Self::Any => chars
                .get(position)
                .is_some_and(|&c| regexp.dot_all || !is_line_terminator(c)),
            Self::LineStart => {
                position == 0
                    || (regexp.multiline && is_line_terminator(chars[position - 1]))
            }
            Self::LineEnd => {
                position == chars.len()
                    || (regexp.multiline && is_line_terminator(chars[position]))
            }
            Self::WordBoundary(negated) => {
                let before = position > 0 && is_word_char(chars[position - 1]);
                let after = position < chars.len() && is_word_char(chars[position]);
                (before != after) != negated
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Check {
    predicate: Predicate,
    /// Characters consumed by earlier predicates, not UTF-8 byte offsets.
    offset: usize,
    /// Total instruction and Clear-range charge through this predicate.
    cost: u64,
}

/// The first choice following the statically checked straight prefix.
/// No input, capture state or heap-allocated plan is retained.
struct BranchStart {
    pc: usize,
    offset: usize,
    /// Charge BEFORE this Split, including any intervening bookkeeping.
    cost: u64,
}

pub(super) struct StartPrefix {
    checks: [Check; MAX_PREFIX_CHECKS],
    len: usize,
    branch: Option<BranchStart>,
}

impl StartPrefix {
    pub(super) fn new(regexp: &BacktrackRegExp) -> Option<Self> {
        let mut prefix = Self {
            checks: [Check {
                predicate: Predicate::Any,
                offset: 0,
                cost: 0,
            }; MAX_PREFIX_CHECKS],
            len: 0,
            branch: None,
        };
        let slots = regexp.group_count.checked_mul(2)?;
        let (mut offset, mut cost) = (0, 0_u64);
        for (pc, instruction) in regexp
            .program
            .iter()
            .take(MAX_PREFIX_INSTRUCTIONS)
            .enumerate()
        {
            cost = cost.checked_add(1)?;
            let (predicate, consumes) = match instruction {
                Inst::Save(slot) if *slot < slots => continue,
                Inst::Clear { from, to } if from <= to && *to <= slots => {
                    cost = cost.checked_add(u64::try_from(to - from).ok()?)?;
                    continue;
                }
                Inst::Mark(register) | Inst::CounterReset(register)
                    if *register < regexp.registers =>
                {
                    continue;
                }
                Inst::Char { c, backward: false } => {
                    let literal = if regexp.ignore_case {
                        regexp.canonicalize(*c)
                    } else {
                        *c
                    };
                    (Predicate::Char(literal), true)
                }
                Inst::Class { class, backward: false } if *class < regexp.classes.len() => {
                    (Predicate::Class(*class), true)
                }
                Inst::Any { backward: false } => (Predicate::Any, true),
                Inst::LineStart => (Predicate::LineStart, false),
                Inst::LineEnd => (Predicate::LineEnd, false),
                Inst::WordBoundary { negated } => (Predicate::WordBoundary(*negated), false),
                Inst::Split { .. } => {
                    prefix.branch = Some(BranchStart { pc, offset, cost: cost - 1 });
                    break;
                }
                // Assertions, backreferences and counter tests need the real
                // capture/register state. Never infer their outcome here.
                _ => break,
            };
            prefix.checks[prefix.len] = Check { predicate, offset, cost };
            prefix.len += 1;
            offset += usize::from(consumes);
            if prefix.len == MAX_PREFIX_CHECKS {
                break;
            }
        }
        (prefix.len != 0 || prefix.branch.is_some()).then_some(prefix)
    }

    pub(super) fn has_multiple_checks(&self) -> bool {
        self.len > 1 || self.branch.is_some()
    }

    /// The exact charge of a fully affordable rejection, otherwise no proof.
    /// Do not debit successful checks: the ordinary VM will execute them if
    /// this prefix cannot reject, and must still see its original allowance.
    fn rejection_cost(
        &self,
        regexp: &BacktrackRegExp,
        chars: &[char],
        start: usize,
        budget: u64,
    ) -> Option<u64> {
        for check in &self.checks[..self.len] {
            if check.cost > budget {
                return None;
            }
            let position = start.checked_add(check.offset)?;
            if !check.predicate.accepts(regexp, chars, position) {
                return Some(check.cost);
            }
        }
        self.branch.as_ref()?.rejection_cost(regexp, chars, start, budget)
    }
}

impl BranchStart {
    /// Explore choices in exactly the executor's preferred/LIFO order. Writes
    /// can be ignored only because a COMPLETE failure undoes all of them; a
    /// read of capture or register state immediately gives up the proof.
    /// The cost includes failed branches, jumps and Clear's extra slot work.
    /// Nothing is debited until the whole candidate has proved impossible.
    fn rejection_cost(
        &self,
        regexp: &BacktrackRegExp,
        chars: &[char],
        start: usize,
        budget: u64,
    ) -> Option<u64> {
        let mut alternatives = [(0_usize, 0_usize); MAX_PREFIX_ALTERNATIVES];
        let mut depth = 0;
        let mut pc = self.pc;
        let mut position = start.checked_add(self.offset)?;
        let mut cost = self.cost;
        let slots = regexp.group_count.checked_mul(2)?;
        if position > chars.len() {
            return None;
        }
        for _ in 0..MAX_PREFIX_INSTRUCTIONS {
            cost = cost.checked_add(1)?;
            if cost > budget {
                return None;
            }
            let (predicate, consumes) = match regexp.program.get(pc)? {
                Inst::Split { first, second } => {
                    // Depth and instruction caps are analysis limits, NOT
                    // guest errors. Even cycles fall back after bounded work.
                    *alternatives.get_mut(depth)? = (*second, position);
                    depth += 1;
                    pc = *first;
                    continue;
                }
                Inst::Jump(target) => {
                    pc = *target;
                    continue;
                }
                Inst::Save(slot) if *slot < slots => {
                    pc = pc.checked_add(1)?;
                    continue;
                }
                Inst::Clear { from, to } if from <= to && *to <= slots => {
                    cost = cost.checked_add(u64::try_from(to - from).ok()?)?;
                    if cost > budget {
                        return None;
                    }
                    pc = pc.checked_add(1)?;
                    continue;
                }
                Inst::Mark(register) | Inst::CounterReset(register)
                    if *register < regexp.registers =>
                {
                    pc = pc.checked_add(1)?;
                    continue;
                }
                Inst::Char { c, backward: false } => {
                    let literal = if regexp.ignore_case { regexp.canonicalize(*c) } else { *c };
                    (Predicate::Char(literal), true)
                }
                Inst::Class { class, backward: false } if *class < regexp.classes.len() => {
                    (Predicate::Class(*class), true)
                }
                Inst::Any { backward: false } => (Predicate::Any, true),
                Inst::LineStart => (Predicate::LineStart, false),
                Inst::LineEnd => (Predicate::LineEnd, false),
                Inst::WordBoundary { negated } => (Predicate::WordBoundary(*negated), false),
                // Match includes a nullable branch: it can never be discarded
                // merely because another branch failed. Look/BackRef and all
                // counter/progress reads also require ordinary execution.
                _ => return None,
            };
            if predicate.accepts(regexp, chars, position) {
                position += usize::from(consumes);
                pc = pc.checked_add(1)?;
            } else if depth == 0 {
                return Some(cost);
            } else {
                depth -= 1;
                (pc, position) = alternatives[depth];
            }
        }
        None
    }
}

impl Run<'_> {
    pub(super) fn skip_prefix_misses(&mut self, at: usize, prefix: &StartPrefix) -> usize {
        let count = (self.input.chars.len() - at).min(MAX_SKIP_BATCH);
        let mut missed = 0;
        while missed < count {
            let Some(cost) = prefix.rejection_cost(
                self.regexp, &self.input.chars, at + missed, self.steps_left,
            ) else {
                break;
            };
            self.steps_left -= cost;
            missed += 1;
        }
        // EOF is deliberately left to execute, including its exact writes
        // before an exhausted budget. No heap scratch or persistent cache.
        missed
    }
}

#[cfg(test)]
mod tests;
