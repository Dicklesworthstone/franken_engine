//! Exact rejection of impossible starts before entering the backtracking VM.
//!
//! Only the initial, straight-line bytecode is considered. A failed predicate
//! before any choice point proves the entire candidate fails. Its preceding
//! capture/register writes would all be undone, so neither the writes nor
//! their undo frames need materializing. Successful prefixes and unaffordable
//! failures still execute normally, including the exact partial refusal state.

use super::{BacktrackRegExp, Inst, Run, is_line_terminator, is_word_char};

const MAX_PREFIX_INSTRUCTIONS: usize = 64;
const MAX_PREFIX_CHECKS: usize = 8;
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

#[derive(Clone, Copy)]
struct Check {
    predicate: Predicate,
    /// Characters consumed by earlier predicates, not UTF-8 byte offsets.
    offset: usize,
    /// Total instruction and Clear-range charge through this predicate.
    cost: u64,
}

pub(super) struct StartPrefix {
    checks: [Check; MAX_PREFIX_CHECKS],
    len: usize,
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
        };
        let slots = regexp.group_count.checked_mul(2)?;
        let (mut offset, mut cost) = (0, 0_u64);
        for instruction in regexp.program.iter().take(MAX_PREFIX_INSTRUCTIONS) {
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
                // A choice, assertion, backreference or counter test needs
                // real execution. In particular, never pick just one branch
                // of an alternation or treat an optional atom as mandatory.
                _ => break,
            };
            prefix.checks[prefix.len] = Check { predicate, offset, cost };
            prefix.len += 1;
            offset += usize::from(consumes);
            if prefix.len == MAX_PREFIX_CHECKS {
                break;
            }
        }
        (prefix.len != 0).then_some(prefix)
    }

    pub(super) fn has_multiple_checks(&self) -> bool {
        self.len > 1
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
            debug_assert!(position <= chars.len());
            let accepts = match check.predicate {
                Predicate::Char(literal) => chars.get(position).is_some_and(|&c| {
                    if regexp.ignore_case {
                        regexp.canonicalize(c) == literal
                    } else {
                        c == literal
                    }
                }),
                Predicate::Class(class) => chars.get(position)
                    .is_some_and(|&c| regexp.class_matches(&regexp.classes[class], c)),
                Predicate::Any => chars.get(position)
                    .is_some_and(|&c| regexp.dot_all || !is_line_terminator(c)),
                Predicate::LineStart => position == 0
                    || (regexp.multiline && is_line_terminator(chars[position - 1])),
                Predicate::LineEnd => position == chars.len()
                    || (regexp.multiline && is_line_terminator(chars[position])),
                Predicate::WordBoundary(negated) => {
                    let before = position > 0 && is_word_char(chars[position - 1]);
                    let after = position < chars.len() && is_word_char(chars[position]);
                    (before != after) != negated
                }
            };
            if !accepts {
                return Some(check.cost);
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
