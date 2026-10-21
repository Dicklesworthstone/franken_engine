use super::*;
use super::super::PreparedInput;

fn compare(regexp: &BacktrackRegExp, text: &str, start: usize, budget: u64, sticky: bool) {
    let input = PreparedInput::new(text);
    let mut actual = Run::new(regexp, &input, budget);
    let mut reference = Run::new(regexp, &input, budget);
    reference.repetitions_disabled = true;
    reference.literal_blocks.disabled = true;
    reference.class_matches.disabled = true;
    actual.slots.fill(Some(17));
    reference.slots.fill(Some(17));
    assert_eq!(actual.search(start, sticky), reference.search(start, sticky),
        "text={text:?} start={start} budget={budget} sticky={sticky}");
    assert_eq!(actual.steps_left, reference.steps_left);
    assert_eq!(actual.slots, reference.slots, "partial captures");
    assert_eq!(actual.registers, reference.registers, "partial marks");
    assert!(actual.stack.is_empty());
    assert!(actual.capture_seen.iter().all(|seen| !seen));
}

#[test]
fn recognize_only_nested_whole_body_captures_with_a_bounded_consuming_body() {
    for pattern in ["(a)*", "((ab))+", "([a-z])*", "(.)*", "(?<=((ab))*)x",
        "(?<word>abc)*", "((((((((a))))))))*"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert!((0..regexp.program.len()).any(|pc| CapturedRepeat::at(&regexp, pc, &mut blocks).is_some()), "{pattern}");
    }
    for pattern in ["(a)*?", "(a|b)*", "(a?)*", "((a)b)*", "(?:(a)(b))*",
        "(a[bc])*", "(?:ab)*", "(a){17}", "(a)?", "(((((((((a)))))))))*"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert!((0..regexp.program.len()).all(|pc| CapturedRepeat::at(&regexp, pc, &mut blocks).is_none()), "{pattern}");
    }
    for width in [1, 2, 31, 32, 33] {
        let regexp = BacktrackRegExp::new(&format!("({})*", "a".repeat(width)), "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert_eq!((0..regexp.program.len()).any(|pc| CapturedRepeat::at(&regexp, pc, &mut blocks).is_some()), width <= 32);
    }
}

#[test]
fn captures_backtracking_assertions_unicode_and_each_budget_match_scalar_dispatch() {
    for (pattern, flags) in [
        ("(a)*a", ""), ("((ab))*ab", ""), ("(ab)+ab", ""),
        ("((ab))*\\1x", ""), ("((ab))*\\2x", ""),
        ("(?=((ab))*x)(ab)*x", ""), ("(?!(ab)*x)(ab)*y", ""),
        ("(?=((ab))*)z|a", ""), ("(?<!(ab)*)x|a", ""),
        ("(?<=((ab))*)x", ""), ("(?<=((ab))*ab)x", ""),
        ("(?:((ab))*c|ab)d", ""), ("(?:(a)*b?)*c", ""),
        ("(([a-c]))*(?=!)", "i"), ("((kſ))*(?=!)", "iu"),
        ("((kſ))*(?=!)", "i"), ("((😀é))*(?=!)", "u"),
        ("((.))*!", "s"), ("((.))*!", ""), ("^(a)*$", "m"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        for text in ["", "a", "aaaa", "ababx", "abababy", "ababababx", "xabcd",
            "Ksks!", "😀é😀é!", "a\nb!", "\na\u{2028}a"] {
            let length = text.chars().count();
            for start in [0, 1, length, length + 1] {
                for budget in (0..=96).chain([127, 255, 4096]) {
                    for sticky in [false, true] {
                        compare(&regexp, text, start, budget, sticky);
                    }
                }
            }
        }
    }
}

fn bare_loop(groups: usize, width: usize, backward: bool) -> BacktrackRegExp {
    let mut regexp = BacktrackRegExp::new("(a)*", "").unwrap();
    regexp.group_count = groups + 1;
    regexp.registers = 1;
    let exit = 5 + 2 * groups + width;
    regexp.program = vec![Inst::Split { first: 1, second: exit }, Inst::Mark(0),
        Inst::Clear { from: 2, to: 2 + 2 * groups }];
    for group in 1..=groups {
        regexp.program.push(Inst::Save(2 * group + usize::from(backward)));
    }
    regexp.program.extend((0..width).map(|i| Inst::Char { c: char::from(b'a' + (i % 3) as u8), backward }));
    for group in (1..=groups).rev() {
        regexp.program.push(Inst::Save(2 * group + usize::from(!backward)));
    }
    regexp.program.extend([Inst::CheckProgress(0), Inst::Jump(0), Inst::Match]);
    regexp
}

#[test]
fn direct_execution_preserves_clear_and_save_refusal_boundaries_and_caller_floor() {
    for groups in [1, 2, 8] {
        for width in [1, 2, 7, 32] {
            for backward in [false, true] {
                let regexp = bare_loop(groups, width, backward);
                for length in [0, 1, width - 1, width, 2 * width + 1] {
                    let mut chars: Vec<_> = (0..length).map(|i| char::from(b'a' + (i % width % 3) as u8)).collect();
                    if backward { chars.reverse(); }
                    let input = PreparedInput::new(&chars.iter().collect::<String>());
                    let start = if backward { length } else { 0 };
                    for budget in 0..=3 * (width + 4 * groups + 5) as u64 {
                        let mut actual = Run::new(&regexp, &input, budget);
                        let mut reference = Run::new(&regexp, &input, budget);
                        reference.repetitions_disabled = true;
                        reference.literal_blocks.disabled = true;
                        actual.registers[0] = 97;
                        reference.registers[0] = 97;
                        for slot in 0..actual.slots.len() {
                            let old = (slot % 3 != 0).then_some(100 + slot);
                            actual.slots[slot] = old;
                            reference.slots[slot] = old;
                        }
                        let prefix = || vec![Frame::Alternative { pc: usize::MAX, position: 13 }];
                        let mut compact = prefix();
                        let mut scalar = prefix();
                        assert_eq!(actual.execute(0, start, &mut compact), reference.execute(0, start, &mut scalar));
                        assert_eq!(actual.steps_left, reference.steps_left);
                        assert_eq!(actual.slots, reference.slots, "g={groups} w={width} b={backward} n={length} budget={budget}");
                        assert_eq!(actual.registers, reference.registers);
                        for stack in [&compact, &scalar] {
                            assert_eq!(stack.len(), 1);
                            assert!(matches!(stack[0], Frame::Alternative { pc: usize::MAX, position: 13 }));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn retained_history_is_bounded_by_group_count_not_repetition_count() {
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    for count in [1, 32, 8192] {
        let regexp = BacktrackRegExp::new("((ab))*", "").unwrap();
        let input = PreparedInput::new(&"ab".repeat(count));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.repetitions_disabled = true;
        let mut compact = Vec::new();
        let mut scalar = Vec::new();
        assert_eq!(actual.execute_inner(0, 0, &mut compact, 0), reference.execute_inner(0, 0, &mut scalar, 0));
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(compact.len(), 8, "two whole-match slots, four nested slots, mark and range");
        assert_eq!(scalar.len(), 10 * count - 2);
        assert_eq!(actual.repeat_dispatches, 1);
    }
}

#[test]
fn malformed_capture_shapes_and_overflowing_program_indices_are_not_fused() {
    for kind in 0..7 {
        let mut regexp = bare_loop(2, 2, false);
        match kind {
            0 => regexp.program[2] = Inst::Clear { from: 1, to: 6 },
            1 => regexp.program[3] = Inst::Save(3),
            2 => regexp.program[4] = Inst::Save(2),
            3 => regexp.program[6] = Inst::Char { c: 'b', backward: true },
            4 => regexp.program[7] = Inst::Save(3),
            5 => regexp.program[9] = Inst::CheckProgress(1),
            _ => regexp.program[10] = Inst::Jump(1),
        }
        assert!(CapturedRepeat::at(&regexp, 0, &mut LiteralBlocks::default()).is_none(), "kind={kind}");
    }
    let regexp = bare_loop(1, 1, false);
    assert!(CapturedRepeat::at(&regexp, usize::MAX, &mut LiteralBlocks::default()).is_none());
}

#[test]
fn global_reuse_and_caught_budget_errors_keep_original_allowance() {
    let regexp = BacktrackRegExp::new("((ab))*(?=!)", "").unwrap();
    let input = PreparedInput::new("abab!xxab!x!");
    for budget in 0..=256 {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.repetitions_disabled = true;
        for start in [0, 5, 8, input.char_len() + 1, 0] {
            assert_eq!(actual.search(start, false), reference.search(start, false));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert!(actual.stack.is_empty());
        }
    }
}

#[test]
fn fixed_external_capture_results_include_greedy_retreat_and_lookbehind() {
    let cases: &[(&str, &str, &str, &[Option<(usize, usize)>])] = &[
        ("((ab))*ab", "", "ababab", &[Some((0, 6)), Some((2, 4)), Some((2, 4))]),
        ("((ab))*\\1x", "", "abababx", &[Some((0, 7)), Some((2, 4)), Some((2, 4))]),
        ("(?<=((ab))*)x", "", "ababx", &[Some((4, 5)), Some((0, 2)), Some((0, 2))]),
        ("((ab))*", "", "x", &[Some((0, 0)), None, None]),
        ("(?=((ab))*)z|a", "", "a", &[Some((0, 1)), None, None]),
        ("((kſ))*!", "iu", "Ksks!", &[Some((0, 7)), Some((4, 6)), Some((4, 6))]),
    ];
    for &(pattern, flags, text, expected) in cases {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        assert_eq!(regexp.exec_at(&PreparedInput::new(text), 0, false).unwrap().as_deref(), Some(expected));
    }
}
