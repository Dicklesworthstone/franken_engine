use super::super::PreparedInput;
use super::*;

fn compare(regexp: &BacktrackRegExp, input: &PreparedInput, start: usize, sticky: bool, budget: u64) {
    let mut actual = Run::new(regexp, input, budget);
    let mut reference = Run::new(regexp, input, budget);
    reference.repetitions_disabled = true;
    reference.literal_blocks.disabled = true;
    actual.slots.fill(Some(17));
    reference.slots.fill(Some(17));
    actual.registers.fill(97);
    reference.registers.fill(97);
    assert_eq!(actual.search(start, sticky), reference.search(start, sticky),
        "start={start} sticky={sticky} budget={budget}");
    assert_eq!(actual.steps_left, reference.steps_left, "instruction charge");
    assert_eq!(actual.slots, reference.slots, "partial refusal captures");
    assert_eq!(actual.registers, reference.registers, "partial refusal marks");
    assert!(actual.stack.is_empty());
    assert!(actual.capture_seen.iter().all(|seen| !seen));
}

#[test]
fn only_complete_non_capturing_literal_loops_are_selected() {
    for pattern in ["(?:ab)*", "(?:abc)+", "((?:abcd)*)", "(?<=((?:ab)*))x", "(?:ab)*?", "(?:abc)+?"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert!((0..regexp.program.len()).any(|pc|
            LiteralRepeat::at(&regexp, pc, &mut blocks).is_some()), "{pattern}");
    }
    for pattern in ["a*", "a*?", "(ab)*", "(?:a?b)*", "(?:ab|cd)*",
        "(?:a[bc])*", "(?:a.)*", "(?:ab){17,}", "(?:ab)?"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert!((0..regexp.program.len()).all(|pc|
            LiteralRepeat::at(&regexp, pc, &mut blocks).is_none()), "{pattern}");
    }
    for width in [2, 3, 31, 32, 33, 64] {
        let pattern = format!("(?:{})*", "a".repeat(width));
        let regexp = BacktrackRegExp::new(&pattern, "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert_eq!((0..regexp.program.len()).any(|pc|
            LiteralRepeat::at(&regexp, pc, &mut blocks).is_some()), width <= 32);
    }
}

#[test]
fn greedy_literals_keep_scalar_semantics_through_captures_and_assertions() {
    for (pattern, flags) in [
        ("((?:ab)*)ab", ""), ("(?:ab)*abc", ""), ("^(?:ab)*b$", ""),
        ("((?:ab)*)(ab+)", ""), ("(?:ab)*x|(?:ab)*y", ""),
        ("(?=((?:ab)*))(?:ab)*ab", ""), ("(?!(?:ab)*x)(?:ab)*y", ""),
        ("(?=((?:ab)*))z|a", ""), ("(?!(?:ab)*z)ab", ""),
        ("(?:(?:ab)*c|ab)d", ""), ("(?:(?:ab)*c?)*d", ""),
        ("(?<=((?:ab)*))x", ""), ("(?<=(?:ab)*ab)x", ""),
        ("(?<!(?:ab)*b)c", ""), ("((?:ab)*)\\1x", ""),
        ("(?:kſ)*(?=!)", "iu"), ("(?:kſ)*(?=!)", "i"),
        ("(?:😀é)*(?=!)", "u"), ("(?<=(?:😀é)*)!", "u"),
        ("(?:a\nb)*c", ""), ("^(?:ab)*$", "m"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in ["", "a", "abab", "xabababc", "ababx", "ababy", "ababd",
            "ababababx", "\nab\u{2028}ab", "Ksks!", "😀é😀é!", "a\nba\nbc"] {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for budget in (0..=80).chain([127, 255, 1024]) {
                    for sticky in [false, true] {
                        compare(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

fn bare_loop(width: usize, backward: bool) -> BacktrackRegExp {
    let mut regexp = BacktrackRegExp::new("(?:ab)*", "").unwrap();
    regexp.registers = 1;
    regexp.program = vec![Inst::Split { first: 1, second: width + 4 }, Inst::Mark(0)];
    regexp.program.extend((0..width).map(|index| Inst::Char {
        c: char::from(b'a' + (index % 3) as u8), backward,
    }));
    regexp.program.extend([Inst::CheckProgress(0), Inst::Jump(0), Inst::Match]);
    regexp
}

#[test]
fn every_literal_and_bookkeeping_refusal_keeps_the_exact_mark() {
    for width in [2, 3, 7, 31, 32] {
        for backward in [false, true] {
            let regexp = bare_loop(width, backward);
            for complete in 0..=2 {
                for suffix in 0..=width {
                    let mut text: Vec<char> = (0..complete * width + suffix)
                        .map(|index| char::from(b'a' + (index % width % 3) as u8)).collect();
                    for mismatching in [false, true] {
                        if mismatching { text.push('!'); }
                        if backward { text.reverse(); }
                        let input = PreparedInput::new(&text.iter().collect::<String>());
                        let start = if backward { input.char_len() } else { 0 };
                        for budget in 0..=(width as u64 + 4) * 4 {
                            let mut actual = Run::new(&regexp, &input, budget);
                            let mut reference = Run::new(&regexp, &input, budget);
                            reference.repetitions_disabled = true;
                            reference.literal_blocks.disabled = true;
                            actual.registers[0] = 97;
                            reference.registers[0] = 97;
                            assert_eq!(actual.execute(0, start, &mut Vec::new()),
                                reference.execute(0, start, &mut Vec::new()),
                                "width={width} backward={backward} complete={complete} suffix={suffix} budget={budget}");
                            assert_eq!(actual.steps_left, reference.steps_left);
                            assert_eq!(actual.registers, reference.registers);
                            assert_eq!(actual.slots, reference.slots);
                        }
                        if backward { text.reverse(); }
                        if mismatching { text.pop(); }
                    }
                }
            }
        }
    }
}

#[test]
fn large_literal_repetitions_keep_two_ordinary_width_choice_frames() {
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    for count in [1, 32, 8192] {
        let regexp = BacktrackRegExp::new("((?:abcd)*)", "").unwrap();
        let input = PreparedInput::new(&"abcd".repeat(count));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.repetitions_disabled = true;
        reference.literal_blocks.disabled = true;
        let mut compact = Vec::new();
        let mut scalar = Vec::new();
        assert_eq!(actual.execute_inner(0, 0, &mut compact, 0),
            reference.execute_inner(0, 0, &mut scalar, 0));
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.repeat_dispatches, 1);
        assert_eq!(compact.len(), 6, "four captures and two repetition frames");
        assert_eq!(scalar.len(), 4 + 2 * count);
    }
}

#[test]
fn greedy_ranges_visit_whole_body_exits_and_keep_caller_stack_floors() {
    for backward in [false, true] {
        let regexp = bare_loop(3, backward);
        let spelling = if backward { "cbacbacba" } else { "abcabcabc" };
        let input = PreparedInput::new(spelling);
        let mut run = Run::new(&regexp, &input, 1000);
        run.registers[0] = 97;
        let mut blocks = LiteralBlocks::default();
        let repeat = LiteralRepeat::at(&regexp, 0, &mut blocks).unwrap();
        let (start, end) = if backward { (9, 0) } else { (0, 9) };
        let mut stack = vec![Frame::Alternative { pc: 777, position: 13 }];
        run.steps_left -= 1; // The caller pays the initial Split.
        assert_eq!(run.execute_literal_greedy(&repeat, 0, start, &mut stack).unwrap(), end);
        assert_eq!(stack.len(), 3);
        for distance in (0..3).rev() {
            let frame = stack.pop().unwrap();
            let position = if backward { start - distance * 3 } else { distance * 3 };
            assert_eq!(run.resume_literal_greedy(frame, &mut stack), (repeat.exit, position));
            assert_eq!(run.registers[0], if distance == 0 { 97 } else if backward {
                position + 3
            } else { position - 3 });
        }
        assert_eq!(stack.len(), 1);
        assert!(matches!(stack[0], Frame::Alternative { pc: 777, position: 13 }));
    }
}

#[test]
fn recognition_rejects_crossed_marks_directions_and_jump_targets() {
    for kind in 0..5 {
        let mut regexp = bare_loop(3, false);
        match kind {
            0 => regexp.program[3] = Inst::Char { c: 'b', backward: true },
            1 => regexp.program[5] = Inst::CheckProgress(1),
            2 => regexp.program[6] = Inst::Jump(1),
            3 => regexp.program[0] = Inst::Split { first: 1, second: 6 },
            _ => regexp.program[3] = Inst::Save(0),
        }
        assert!(LiteralRepeat::at(&regexp, 0, &mut LiteralBlocks::default()).is_none());
    }
}

#[test]
fn repeated_searches_and_refusals_do_not_renew_the_shared_allowance() {
    let regexp = BacktrackRegExp::new("((?:ab)*)(?=!)", "").unwrap();
    let input = PreparedInput::new("abab!xxab!x!");
    for budget in 0..=256 {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.repetitions_disabled = true;
        reference.literal_blocks.disabled = true;
        for start in [0, 5, 10, input.char_len() + 1, 0] {
            assert_eq!(actual.search(start, false), reference.search(start, false));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert!(actual.stack.is_empty());
        }
    }
}

#[test]
fn lazy_literal_loops_keep_exit_order_captures_and_refusal_state() {
    for (pattern, flags) in [
        ("((?:ab)*?)ab", ""), ("(?:ab)*?abc", ""), ("^(?:ab)*?b$", ""),
        ("((?:ab)*?)(ab+)", ""), ("(?:ab)*?x|(?:ab)*?y", ""),
        ("(?=((?:ab)*?))(?:ab)*?ab", ""), ("(?!(?:ab)*?x)(?:ab)*?y", ""),
        ("(?:(?:ab)*?c|ab)d", ""), ("(?:(?:ab)*?c?)*d", ""),
        ("(?<=((?:ab)*?))x", ""), ("(?<=(?:ab)*?ab)x", ""),
        ("(?<!(?:ab)*?b)c", ""), ("((?:ab)*?)\\1x", ""),
        ("(?:kſ)*?(?=!)", "iu"), ("(?:kſ)*?(?=!)", "i"),
        ("(?:😀é)*?(?=!)", "u"), ("(?<=(?:😀é)*?)!", "u"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in ["", "a", "abab", "xabababc", "ababx", "ababy", "ababd",
            "ababababx", "\nab\u{2028}ab", "Ksks!", "😀é😀é!"] {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for budget in (0..=80).chain([127, 255, 1024]) {
                    for sticky in [false, true] {
                        compare(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn lazy_literal_extensions_preserve_each_character_and_mark_refusal_boundary() {
    for width in [2, 3, 7, 31, 32] {
        for backward in [false, true] {
            let mut regexp = bare_loop(width, backward);
            regexp.program[0] = Inst::Split { first: width + 4, second: 1 };
            // Force every lazy exit to fail, exercising all later extensions.
            regexp.program[width + 4] = Inst::Char { c: '!', backward };
            regexp.program.push(Inst::Match);
            for length in 0..=width * 2 + 1 {
                let mut chars: Vec<_> = (0..length)
                    .map(|index| char::from(b'a' + (index % width % 3) as u8)).collect();
                if backward { chars.reverse(); }
                let input = PreparedInput::new(&chars.iter().collect::<String>());
                let start = if backward { input.char_len() } else { 0 };
                for budget in 0..=(width as u64 + 5) * 4 {
                    let mut actual = Run::new(&regexp, &input, budget);
                    let mut reference = Run::new(&regexp, &input, budget);
                    reference.repetitions_disabled = true;
                    reference.literal_blocks.disabled = true;
                    actual.registers[0] = 97;
                    reference.registers[0] = 97;
                    assert_eq!(actual.execute(0, start, &mut Vec::new()),
                        reference.execute(0, start, &mut Vec::new()));
                    assert_eq!(actual.steps_left, reference.steps_left);
                    assert_eq!(actual.registers, reference.registers,
                        "width={width} backward={backward} length={length} budget={budget}");
                }
            }
        }
    }
}

#[test]
fn lazy_literal_success_retains_one_choice_and_does_not_read_a_later_body() {
    for count in [0, 1, 32, 8192] {
        let regexp = BacktrackRegExp::new("((?:abcd)*?)!", "").unwrap();
        let input = PreparedInput::new(&format!("{}!{}", "abcd".repeat(count), "abcd".repeat(8192)));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.repetitions_disabled = true;
        reference.literal_blocks.disabled = true;
        let mut compact = Vec::new();
        let mut scalar = Vec::new();
        assert_eq!(actual.execute_inner(0, 0, &mut compact, 0),
            reference.execute_inner(0, 0, &mut scalar, 0));
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(compact.len(), 5, "four captures and one lazy continuation");
        assert_eq!(scalar.len(), 5 + count);
    }
    // A zero-iteration success has no budget for a Mark or a body character.
    let regexp = BacktrackRegExp::new("((?:abcd)*?)", "").unwrap();
    let input = PreparedInput::new(&"abcd".repeat(8192));
    let mut actual = Run::new(&regexp, &input, 6);
    assert!(actual.search(0, true).unwrap().is_some());
    assert_eq!(actual.steps_left, 0);
    assert_eq!(actual.registers[0], 0);
}

#[test]
fn mixed_literal_loops_reuse_caches_and_work_without_retaining_prior_choices() {
    let regexp = BacktrackRegExp::new("((?:ab)*?)(?:cd)*(?=!)", "").unwrap();
    let input = PreparedInput::new("ababcd!xxabcdcd!x!");
    for budget in 0..=256 {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.repetitions_disabled = true;
        reference.literal_blocks.disabled = true;
        for start in [0, 7, 14, input.char_len() + 1, 0] {
            assert_eq!(actual.search(start, false), reference.search(start, false));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert!(actual.stack.is_empty());
        }
    }
}

#[test]
fn literal_loop_success_failure_and_refusal_preserve_the_callers_stack_prefix() {
    for greedy in [false, true] {
        for backward in [false, true] {
            let mut regexp = bare_loop(3, backward);
            if !greedy {
                regexp.program[0] = Inst::Split { first: 7, second: 1 };
            }
            regexp.program[7] = Inst::Char { c: '!', backward };
            regexp.program.push(Inst::Match);
            for succeeds in [false, true] {
                let mut text: Vec<_> = "abcabcabc".chars().collect();
                if succeeds {
                    text.push('!');
                }
                if backward {
                    text.reverse();
                }
                let input = PreparedInput::new(&text.iter().collect::<String>());
                let start = if backward { input.char_len() } else { 0 };
                for budget in 0..=64 {
                    let mut actual = Run::new(&regexp, &input, budget);
                    let mut reference = Run::new(&regexp, &input, budget);
                    reference.repetitions_disabled = true;
                    reference.literal_blocks.disabled = true;
                    actual.registers[0] = 97;
                    reference.registers[0] = 97;
                    // Reaching either frame is an error: they belong to the
                    // caller, and the invalid PC must never be executed.
                    let prefix = || vec![
                        Frame::Alternative { pc: usize::MAX, position: usize::MAX },
                        Frame::Register { register: 0, old: 1234 },
                    ];
                    let mut compact = prefix();
                    let mut scalar = prefix();
                    assert_eq!(actual.execute(0, start, &mut compact),
                        reference.execute(0, start, &mut scalar));
                    assert_eq!(actual.steps_left, reference.steps_left);
                    assert_eq!(actual.registers, reference.registers);
                    assert_eq!(actual.slots, reference.slots);
                    for stack in [&compact, &scalar] {
                        assert_eq!(stack.len(), 2);
                        assert!(matches!(stack[0], Frame::Alternative {
                            pc: usize::MAX, position: usize::MAX,
                        }));
                        assert!(matches!(stack[1], Frame::Register {
                            register: 0, old: 1234,
                        }));
                    }
                }
            }
        }
    }
}
