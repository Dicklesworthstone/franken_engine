//! Differential checks against the pre-workspace executor. The reference
//! owns a separate stack per invocation and is never compiled in production.

use super::*;
use super::super::{CaptureRetention, CompiledRegExp, RetentionBudget};

impl Run<'_> {
    fn execute_reference(
        &mut self,
        start_pc: usize,
        start_position: usize,
    ) -> Result<Option<usize>, BacktrackError> {
        let regexp = self.regexp;
        let input = self.input;
        let chars = &input.chars;
        let mut stack: Vec<Frame> = Vec::new();
        let mut pc = start_pc;
        let mut position = start_position;
        loop {
            if self.steps_left == 0 {
                return Err(BacktrackError::StepBudget);
            }
            self.steps_left -= 1;
            let advanced = match &regexp.program[pc] {
                Inst::Char { c, backward } => self.step(position, *backward, |input| {
                    if regexp.ignore_case {
                        regexp.canonicalize(input) == regexp.canonicalize(*c)
                    } else {
                        input == *c
                    }
                }),
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
                    // Saving and diffing every slot costs the slot count.
                    self.charge(self.slots.len())?;
                    let before = self.slots.clone();
                    let matched = self.execute_reference(*body, position)?.is_some();
                    if matched == *negated {
                        // Failed: a failed sub-run has undone its changes;
                        // a matching negative one has not.
                        self.slots = before;
                        None
                    } else {
                        if !negated {
                            // Keep the captures, undoably.
                            for (slot, old) in before.into_iter().enumerate() {
                                if self.slots[slot] != old {
                                    stack.push(Frame::Slot { slot, old });
                                }
                            }
                        }
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
                    match stack.pop() {
                        None => return Ok(None),
                        Some(Frame::Slot { slot, old }) => self.slots[slot] = old,
                        Some(Frame::Register { register, old }) => {
                            self.registers[register] = old;
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
}

fn reference_search(
    regexp: &BacktrackRegExp,
    input: &PreparedInput,
    start: usize,
    sticky: bool,
    budget: u64,
) -> (Result<Option<Captures>, BacktrackError>, u64) {
    let mut run = Run::new(regexp, input, budget);
    let result = (|| {
        for at in start..=input.char_len() {
            run.slots.fill(None);
            if run.execute_reference(0, at)?.is_some() {
                return Ok(Some(
                    run.slots
                        .chunks(2)
                        .map(|pair| match (pair[0], pair[1]) {
                            (Some(from), Some(to)) => {
                                Some((input.byte_offset(from), input.byte_offset(to)))
                            }
                            _ => None,
                        })
                        .collect(),
                ));
            }
            if sticky {
                break;
            }
        }
        Ok(None)
    })();
    (result, run.steps_remaining())
}

#[test]
fn shared_stack_matches_reference_captures_and_every_budget_boundary() {
    let patterns = [
        "a|bc",
        "((a)|(b))+",
        "(a?b??)*",
        r"(?=(a+))a*b\1",
        r"(?=(a|ab))\1c",
        r"(a)(?!(b|c))|b",
        r"(?<=(a+)(b+))c",
        r"(?<!(a|b))c|a",
        r"(?=(a(?=(b))))ab|b",
        r"(?!(?=(a))a)b|a",
        r"(?:(a)|b){0,20}?c",
        r"(?<=(a){1,20})(b)?",
    ];
    let mut texts = vec![String::new(), "aababc".to_string(), "éab😀c".to_string()];
    for length in 1..=5 {
        for bits in 0..(1_usize << length) {
            texts.push(
                (0..length)
                    .map(|bit| if bits & (1 << bit) == 0 { 'a' } else { 'b' })
                    .collect(),
            );
        }
    }
    for pattern in patterns {
        let regexp = BacktrackRegExp::new(pattern, "u").unwrap();
        for text in &texts {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for sticky in [false, true] {
                    for budget in [0, 1, 2, 3, 4, 5, 7, 9, 16, 31, 64, 256, 4096] {
                        let expected = reference_search(&regexp, &input, start, sticky, budget);
                        let mut run = Run::new(&regexp, &input, budget);
                        let result = run.search(start, sticky);
                        assert_eq!(
                            (result, run.steps_remaining()),
                            expected,
                            "/{pattern}/u text={text:?} start={start} sticky={sticky} budget={budget}"
                        );
                        assert!(run.stack.is_empty());
                        assert!(run.stack.capacity() <= MAX_RETAINED_FRAMES);
                    }
                }
            }
        }
    }
}

#[test]
fn reused_global_searches_match_fresh_runs_without_renewing_the_budget() {
    let text = "baaaababcéab😀ab";
    let input = PreparedInput::new(text);
    for pattern in [
        r"(?<=(a))(b)|a",
        r"(?=(a+))a|b",
        r"(?:(a)|b){0,20}",
        r"(?!(a))b|a",
        r"((a)|(b))+",
        "b*",
    ] {
        let regexp = BacktrackRegExp::new(pattern, "u").unwrap();
        for budget in [0, 1, 8, 32, 128, 512, 4096] {
            let mut run = Run::new(&regexp, &input, budget);
            let mut remaining = budget;
            let mut at = 0;
            while at <= input.char_len() {
                let expected = reference_search(&regexp, &input, at, false, remaining);
                let actual = run.search(at, false);
                remaining = expected.1;
                assert_eq!(actual, expected.0, "{pattern} at={at} budget={budget}");
                assert_eq!(run.steps_remaining(), remaining);
                assert!(run.stack.is_empty());
                let Ok(Some(spans)) = actual else {
                    break;
                };
                let (from, to) = spans[0].unwrap();
                at = input.char_index_at_byte(to) + usize::from(from == to);
            }
        }
    }
}

#[test]
fn small_searches_reuse_work_buffers_after_success_failure_and_nested_assertions() {
    let regexp = BacktrackRegExp::new(r"(?<=(a))b|(?!(c))a|z", "").unwrap();
    let input = PreparedInput::new("abac");
    let mut run = Run::new(&regexp, &input, 1_000_000);
    // Warm all paths, so later visits may neither replace slots nor grow frames.
    for at in [0, 1, 2, 3, 4] {
        let _ = run.search(at, true).unwrap();
    }
    let slots = run.slots.as_ptr();
    let registers = run.registers.as_ptr();
    let frames = run.stack.as_ptr();
    let capacity = run.stack.capacity();
    assert!(capacity > 0);
    for _ in 0..64 {
        for at in [0, 1, 2, 3, 4] {
            let expected = reference_search(&regexp, &input, at, true, run.steps_remaining());
            assert_eq!(run.search(at, true), expected.0);
            assert_eq!(run.steps_remaining(), expected.1);
            assert_eq!(run.slots.as_ptr(), slots);
            assert_eq!(run.registers.as_ptr(), registers);
            assert_eq!(run.stack.as_ptr(), frames);
            assert_eq!(run.stack.capacity(), capacity);
            assert!(run.stack.is_empty());
        }
    }
}

#[test]
fn search_releases_an_oversized_stack_instead_of_retaining_an_adversarial_peak() {
    let regexp = BacktrackRegExp::new("a*", "").unwrap();
    let text = "a".repeat(MAX_RETAINED_FRAMES * 2);
    let input = PreparedInput::new(&text);
    let mut run = Run::new(&regexp, &input, 1_000_000);
    assert_eq!(run.search(0, true).unwrap(), Some(vec![Some((0, text.len()))]));
    assert_eq!(run.stack.capacity(), 0);
    assert_eq!(
        run.search(input.char_len(), true).unwrap(),
        Some(vec![Some((text.len(), text.len()))])
    );
    assert!(run.stack.capacity() <= MAX_RETAINED_FRAMES);
}

#[test]
fn success_exhaustion_and_retry_do_not_refresh_the_shared_work_allowance() {
    let regexp = BacktrackRegExp::new("a", "").unwrap();
    let input = PreparedInput::new("aa");
    let mut run = Run::new(&regexp, &input, 9);
    assert_eq!(run.search(0, true).unwrap(), Some(vec![Some((0, 1))]));
    assert_eq!(run.search(1, true).unwrap(), Some(vec![Some((1, 2))]));
    assert_eq!(run.steps_remaining(), 1);
    assert_eq!(run.search(2, true), Err(BacktrackError::StepBudget));
    assert!(run.stack.is_empty());
    assert_eq!(run.search(0, true), Err(BacktrackError::StepBudget));
    assert_eq!(run.steps_remaining(), 0);
}

#[test]
fn global_retention_modes_keep_exact_spans_and_charges() {
    let regexp = BacktrackRegExp::new(r"(?<=(a))(b)|a", "").unwrap();
    let engine = CompiledRegExp::Backtracking(std::rc::Rc::new(regexp));
    let full = vec![
        vec![Some((0, 1)), None, None],
        vec![Some((1, 2)), Some((0, 1)), Some((1, 2))],
        vec![Some((2, 3)), None, None],
        vec![Some((3, 4)), Some((2, 3)), Some((3, 4))],
    ];
    for retention in [
        CaptureRetention::AllGroups,
        CaptureRetention::WholeMatchExceptLast,
    ] {
        let mut expected = full.clone();
        if retention == CaptureRetention::WholeMatchExceptLast {
            for spans in &mut expected[..3] {
                spans.truncate(1);
            }
        }
        let exact: u64 = expected
            .iter()
            .map(|spans| RetentionBudget::captures_bytes(spans.len()))
            .sum();
        let mut budget = RetentionBudget::new(exact);
        assert_eq!(
            engine.all_captures("abab", retention, &mut budget).unwrap(),
            expected
        );
        assert_eq!(budget.used(), exact);
        assert!(
            engine
                .all_captures("abab", retention, &mut RetentionBudget::new(exact - 1))
                .is_err()
        );
    }
}
