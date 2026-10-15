//! Constant-space backtracking choices for a greedy, one-character repetition.
//!
//! Recognize only the compiler's exact Split/Mark/atom/CheckProgress/Jump
//! loop. Capturing or nullable bodies, lazy choices and counted loops keep
//! ordinary execution. A compact range retains EVERY earlier exit position,
//! not just the greedy result, and reconstructs the mark's exact old value.
//! The existing frame width and instruction/refusal boundaries stay unchanged.

use super::{BacktrackError, BacktrackRegExp, Frame, Inst, Run, is_line_terminator};

#[derive(Clone, Copy)]
enum Atom {
    Char(char),
    Class(usize),
    Any,
}

pub(super) struct GreedyRepeat {
    pub(super) register: usize,
    pub(super) exit: usize,
    atom: Atom,
    backward: bool,
}

impl GreedyRepeat {
    pub(super) fn at(regexp: &BacktrackRegExp, pc: usize) -> Option<Self> {
        let exit = pc.checked_add(5)?;
        let [Inst::Split { first, second }, Inst::Mark(register), atom,
            Inst::CheckProgress(progress), Inst::Jump(head)] = regexp.program.get(pc..exit)?
        else {
            return None;
        };
        if *first != pc + 1 || *second != exit || *head != pc
            || register != progress || *register >= regexp.registers
            || exit >= regexp.program.len()
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
        Some(Self { register: *register, exit, atom, backward })
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

    /// The dispatch loop already paid for Split. A successful iteration pays
    /// Mark + atom + CheckProgress + Jump + the NEXT Split (five steps).
    /// A failing atom pays Mark + atom, then restores the mark and takes the
    /// just-pushed exit choice, exactly as ordinary stack unwinding does.
    pub(super) fn execute_after_split(
        &self,
        regexp: &BacktrackRegExp,
        chars: &[char],
        mut position: usize,
        mark: &mut usize,
        steps_left: &mut u64,
    ) -> Result<usize, BacktrackError> {
        debug_assert!(position <= chars.len());
        loop {
            if *steps_left >= 5 {
                if !self.accepts(regexp, chars, position) {
                    *steps_left -= 2;
                    return Ok(position);
                }
                *steps_left -= 5;
                *mark = position;
                position = if self.backward { position - 1 } else { position + 1 };
                continue;
            }
            // Preserve partial refusal state too: a refusal before Mark must
            // not write it; a refusal after Mark keeps its new value; a paid
            // failing atom restores it. A paid successful atom with fewer
            // than three steps left must exhaust before the next Mark.
            if *steps_left == 0 {
                return Err(BacktrackError::StepBudget);
            }
            *steps_left -= 1;
            let old = *mark;
            *mark = position;
            if *steps_left == 0 {
                return Err(BacktrackError::StepBudget);
            }
            *steps_left -= 1;
            if !self.accepts(regexp, chars, position) {
                *mark = old;
                return Ok(position);
            }
            *steps_left = 0;
            return Err(BacktrackError::StepBudget);
        }
    }

    /// Two ordinary-width frames, independent of the number of repetitions.
    /// The Register directly below the range keeps the pre-loop mark. It is
    /// consumed with the final alternative, never restored after that choice.
    pub(super) fn push_choices(
        &self,
        stack: &mut Vec<Frame>,
        start: usize,
        end: usize,
        old: usize,
    ) {
        if start == end {
            return;
        }
        stack.push(Frame::Register { register: self.register, old });
        stack.push(if self.backward {
            debug_assert!(end < start);
            Frame::RepeatBackward { pc: self.exit, position: end + 1, start }
        } else {
            debug_assert!(end > start);
            Frame::RepeatForward { pc: self.exit, position: end - 1, start }
        });
    }
}

impl Run<'_> {
    /// Expand just the next greedy exit. Tail writes have already unwound,
    /// so the paired Register is immediately below the popped range. Assertion
    /// commit/discard removes BOTH frames without expansion, as it did the
    /// corresponding scalar choices and register history.
    pub(super) fn resume_repeat(&mut self, frame: Frame, stack: &mut Vec<Frame>) -> (usize, usize) {
        let (pc, position, start, backward) = match frame {
            Frame::RepeatForward { pc, position, start } => (pc, position, start, false),
            Frame::RepeatBackward { pc, position, start } => (pc, position, start, true),
            _ => unreachable!("only a repetition range is resumed here"),
        };
        let Some(Frame::Register { register, old }) = stack.last() else {
            unreachable!("a repetition range is paired with its initial register undo");
        };
        if position == start {
            self.registers[*register] = *old;
            stack.pop();
        } else {
            let previous = if backward { position + 1 } else { position - 1 };
            self.registers[*register] = previous;
            stack.push(if backward {
                Frame::RepeatBackward { pc, position: previous, start }
            } else {
                Frame::RepeatForward { pc, position: previous, start }
            });
        }
        (pc, position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::PreparedInput;

    fn compare(regexp: &BacktrackRegExp, input: &PreparedInput, start: usize, sticky: bool, budget: u64) {
        let mut actual = Run::new(regexp, input, budget);
        let mut reference = Run::new(regexp, input, budget);
        reference.repetitions_disabled = true;
        actual.slots.fill(Some(17));
        reference.slots.fill(Some(17));
        actual.registers.fill(23);
        reference.registers.fill(23);
        assert_eq!(actual.search(start, sticky), reference.search(start, sticky),
            "start={start} sticky={sticky} budget={budget}");
        assert_eq!(actual.steps_left, reference.steps_left, "exact instruction allowance");
        assert_eq!(actual.slots, reference.slots, "including partial refusal captures");
        assert_eq!(actual.registers, reference.registers, "including partial refusal marks");
        assert!(actual.stack.is_empty());
        assert!(actual.capture_seen.iter().all(|seen| !seen));
    }

    #[test]
    fn only_non_capturing_single_atom_greedy_loops_are_selected() {
        for pattern in ["a*", "a+", "[a-z]*", ".*", "(a*)", "(?<=a*)b"] {
            let regexp = BacktrackRegExp::new(pattern, "").unwrap();
            assert!((0..regexp.program.len()).any(|pc| GreedyRepeat::at(&regexp, pc).is_some()), "{pattern}");
        }
        for pattern in ["a*?", "(a)*", "(?:ab)*", "(?:a?)*", "a?", "a{0,2}", "a{17,}", "a|b"] {
            let regexp = BacktrackRegExp::new(pattern, "").unwrap();
            assert!((0..regexp.program.len()).all(|pc| GreedyRepeat::at(&regexp, pc).is_none()), "{pattern}");
        }
    }

    #[test]
    fn repeats_keep_exact_captures_marks_and_budgets_through_backtracking_and_assertions() {
        for (pattern, flags) in [
            ("(a*)a", ""), ("a*aab", ""), ("^a*b$", ""),
            ("(a*)(a+)", ""), ("a*b|a*c", ""),
            ("(?=(a*))a*a", ""), ("(?!(a*b))a*c", ""),
            ("(?=(a*))b|a", ""), ("(?!(a*))b|a", ""),
            ("(?:(a*)b|a)c", ""), ("(?:(a*)a?)*b", ""),
            ("(?<=([a-z]*))b", ""), ("(?<=(a*)a)b", ""),
            ("(?<!([a-z]*)b)c", ""), ("(a*)\\1b", ""),
            ("([a-c]*)(?=!)", "i"), ("(k*)(?=!)", "iu"),
            ("(k*)(?=!)", "i"), ("(😀*)(?=!)", "u"),
            (".*a", "s"), (".*a", ""), ("^a*$", "m"),
            ("((?:😀)*)(?!(?:.|(.)))", "u"),
        ] {
            let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
            for text in ["", "a", "aaaa", "xaaab", "aaac", "aabac", "\na\u{2028}a", "Kk!", "😀😀!", "é😀ba\n\na"] {
                let input = PreparedInput::new(text);
                for start in 0..=input.char_len() + 1 {
                    for budget in (0..=96).chain([127, 255, 1024]) {
                        for sticky in [false, true] {
                            compare(&regexp, &input, start, sticky, budget);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn forward_and_backward_scans_have_every_scalar_partial_refusal_state() {
        let input = PreparedInput::new("aaaaa");
        for backward in [false, true] {
            let mut regexp = BacktrackRegExp::new("a*", "").unwrap();
            regexp.program = vec![
                Inst::Split { first: 1, second: 5 }, Inst::Mark(0),
                Inst::Char { c: 'a', backward }, Inst::CheckProgress(0), Inst::Jump(0),
                Inst::Match,
            ];
            let repeat = GreedyRepeat::at(&regexp, 0).unwrap();
            for start in 0..=input.char_len() {
                for budget in 0..=40 {
                    let mut actual = Run::new(&regexp, &input, budget);
                    let mut reference = Run::new(&regexp, &input, budget);
                    reference.repetitions_disabled = true;
                    actual.registers[0] = 97;
                    reference.registers[0] = 97;
                    assert_eq!(actual.execute(0, start, &mut Vec::new()), reference.execute(0, start, &mut Vec::new()));
                    assert_eq!(actual.steps_left, reference.steps_left);
                    assert_eq!(actual.registers, reference.registers,
                        "backward={backward} start={start} budget={budget}");
                    // Test the scanner seam too: its caller has already paid Split.
                    if budget > 0 {
                        let mut mark = 97;
                        let mut left = budget - 1;
                        let result = repeat.execute_after_split(&regexp, &input.chars, start, &mut mark, &mut left);
                        match result {
                            Ok(end) => {
                                // The reference then paid Match, or refused immediately before it.
                                assert_eq!(mark, reference.registers[0]);
                                if left != 0 {
                                    assert_eq!(left - 1, reference.steps_left);
                                    assert_eq!(end, if backward { 0 } else { input.char_len() });
                                }
                            }
                            Err(_) => {
                                assert_eq!(mark, reference.registers[0]);
                                assert_eq!(left, reference.steps_left);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn long_repetitions_keep_two_choice_frames_without_widening_ordinary_frames() {
        // A wider enum would tax every non-optimized path. These range payloads
        // fit the existing Slot variant's three-word maximum payload.
        assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
        for length in [1, 32, 8192] {
            let regexp = BacktrackRegExp::new("(a*)", "").unwrap();
            let input = PreparedInput::new(&"a".repeat(length));
            let mut actual = Run::new(&regexp, &input, 1_000_000);
            let mut reference = Run::new(&regexp, &input, 1_000_000);
            reference.repetitions_disabled = true;
            let mut compact = Vec::new();
            let mut scalar = Vec::new();
            assert_eq!(actual.execute_inner(0, 0, &mut compact, 0), reference.execute_inner(0, 0, &mut scalar, 0));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert_eq!(actual.repeat_dispatches, 1);
            assert_eq!(compact.len(), 6, "four capture writes plus the two range frames");
            assert_eq!(scalar.len(), 4 + 2 * length);
        }
    }

    #[test]
    fn compressed_choices_expand_all_positions_and_restore_the_initial_mark_last() {
        let mut regexp = BacktrackRegExp::new("a*", "").unwrap();
        let input = PreparedInput::new("aaaaaa");
        for backward in [false, true] {
            regexp.program[3] = Inst::Char { c: 'a', backward };
            let repeat = GreedyRepeat::at(&regexp, 1).unwrap();
            for length in 1..=5 {
                let (start, end) = if backward { (length, 0) } else { (0, length) };
                let mut stack = Vec::new();
                repeat.push_choices(&mut stack, start, end, 97);
                let mut run = Run::new(&regexp, &input, 1000);
                for distance in (0..length).rev() {
                    let at = if backward { start - distance } else { start + distance };
                    let frame = stack.pop().unwrap();
                    assert_eq!(run.resume_repeat(frame, &mut stack), (repeat.exit, at));
                    assert_eq!(run.registers[repeat.register], if distance == 0 {
                        97
                    } else if backward {
                        at + 1
                    } else {
                        at - 1
                    });
                    assert_eq!(stack.len(), if distance == 0 { 0 } else { 2 });
                }
            }
        }
    }

    #[test]
    fn reused_global_searches_and_caught_refusals_do_not_renew_the_allowance() {
        let regexp = BacktrackRegExp::new("(a*)(?=!)", "").unwrap();
        let input = PreparedInput::new("aaa!xxaa!x!");
        for budget in 0..=256 {
            let mut actual = Run::new(&regexp, &input, budget);
            let mut reference = Run::new(&regexp, &input, budget);
            reference.repetitions_disabled = true;
            for (start, sticky) in [(0, false), (4, false), (8, true), (0, true), (10, false), (99, false)] {
                assert_eq!(actual.search(start, sticky), reference.search(start, sticky));
                assert_eq!(actual.steps_left, reference.steps_left);
                assert_eq!(actual.slots, reference.slots);
                assert_eq!(actual.registers, reference.registers);
            }
        }
    }

    #[test]
    fn greedy_repeat_captures_and_backtracking_match_node_reference_results() {
        // Expected strings and UTF-16 indices re-executed with Node v22.16.0.
        // These are fixed semantic fixtures, not engine-versus-Node timings.
        fn check(pattern: &str, flags: &str, text: &str, expected: Option<(usize, Vec<Option<&str>>)>) {
            let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
            let input = PreparedInput::new(text);
            let actual = regexp.exec_at(&input, 0, false).unwrap().map(|spans| {
                let start = spans[0].unwrap().0;
                let groups = spans.iter().map(|span| span.map(|(from, to)| &text[from..to])).collect::<Vec<_>>();
                (text[..start].encode_utf16().count(), groups)
            });
            assert_eq!(actual, expected, "/{pattern}/{flags} text={text:?}");
        }
        check("(a*)a", "", "aaaa", Some((0, vec![Some("aaaa"), Some("aaa")])));
        check("(a*)(a+)", "", "aaaa", Some((0, vec![Some("aaaa"), Some("aaa"), Some("a")])));
        check("a*aab", "", "aaaaab", Some((0, vec![Some("aaaaab")])));
        check("a*b|a*c", "", "aaac", Some((0, vec![Some("aaac")])));
        check("(?=(a*))a*a", "", "aaaa", Some((0, vec![Some("aaaa"), Some("aaaa")])));
        check("(?!(a*b))a*c", "", "aaac", Some((0, vec![Some("aaac"), None])));
        check("(?=(a*))b|a", "", "a", Some((0, vec![Some("a"), None])));
        check("(?!(a*))b|a", "", "a", Some((0, vec![Some("a"), None])));
        check("(?:(a*)b|a)c", "", "aaac", Some((2, vec![Some("ac"), None])));
        check(r"(a*)\1b", "", "aaaab", Some((0, vec![Some("aaaab"), Some("aa")])));
        check("(?<=([a-z]*))b", "", "aaab", Some((3, vec![Some("b"), Some("aaa")])));
        check("(?<=(a*)a)b", "", "aaab", Some((3, vec![Some("b"), Some("aa")])));
        check("(?<!([a-z]*)b)c", "", "aaabc", None);
        check("(k*)(?=!)", "iu", "Kk!", Some((0, vec![Some("Kk"), Some("Kk")])));
        check("(😀*)(?=!)", "u", "😀😀!", Some((0, vec![Some("😀😀"), Some("😀😀")])));
        check(".*a", "s", "x\nza", Some((0, vec![Some("x\nza")])));
        check("(a)*", "", "aaa", Some((0, vec![Some("aaa"), Some("a")])));
    }
}
