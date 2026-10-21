//! Exercise the actual executor with and without counted-body compaction.
//! Intermediate register/capture state and remaining fuel are part of the oracle.

use super::super::PreparedInput;
use super::*;

fn direct_loop(width: usize, rotation: usize, backward: bool, minimum: usize) -> (BacktrackRegExp, String) {
    let mut regexp = BacktrackRegExp::new("[0-9]", "").unwrap();
    assert!(!regexp.classes.is_empty());
    regexp.registers = 2;
    let exit = width + 4;
    regexp.program = vec![
        Inst::CountedLoop { counter: 0, min: minimum, max: Some(minimum), greedy: true, body: 1, exit },
        Inst::Mark(1),
    ];
    let mut word = String::new();
    for index in 0..width {
        let (instruction, character) = match (index + rotation) % 3 {
            0 => (Inst::Char { c: 'a', backward }, 'a'),
            1 => (Inst::Class { class: 0, backward }, '7'),
            _ => (Inst::Any { backward }, 'z'),
        };
        regexp.program.push(instruction);
        word.push(character);
    }
    regexp.program.extend([
        Inst::CounterStep { counter: 0, mark: 1, min: minimum },
        Inst::Jump(0),
        Inst::Match,
    ]);
    (regexp, word)
}

fn compare_search(regexp: &BacktrackRegExp, text: &str, starts: &[usize], budget: u64) {
    let input = PreparedInput::new(text);
    let mut actual = Run::new(regexp, &input, budget);
    let mut reference = Run::new(regexp, &input, budget);
    reference.repetitions_disabled = true;
    reference.literal_blocks.disabled = true;
    reference.class_matches.disabled = true;
    for &start in starts {
        assert_eq!(actual.search(start, false), reference.search(start, false));
        assert_eq!(actual.steps_left, reference.steps_left, "remaining fuel");
        assert_eq!(actual.slots, reference.slots, "partial captures");
        assert_eq!(actual.registers, reference.registers, "partial registers");
        assert!(actual.stack.is_empty());
        assert!(actual.capture_seen.iter().all(|seen| !seen));
    }
}

#[test]
fn mixed_recognition_requires_a_complete_consuming_same_direction_body() {
    for width in [2, 3, 7, 31, 32, 33, 64] {
        for rotation in 0..3 {
            for backward in [false, true] {
                let (regexp, _) = direct_loop(width, rotation, backward, 17);
                let repeat = CountedRepeat::at(&regexp, 0);
                assert_eq!(repeat.is_some(), width <= LITERAL_WIDTH);
                if let Some(repeat) = repeat {
                    assert_eq!(repeat.width, width);
                    assert_eq!(repeat.backward, backward);
                    assert!(matches!(repeat.atom, Atom::Sequence(2)));
                }
            }
        }
    }
    for replacement in [
        Inst::Class { class: usize::MAX, backward: false },
        Inst::Class { class: 0, backward: true },
        Inst::Any { backward: true },
        Inst::Char { c: 'x', backward: true },
        Inst::Save(0), Inst::Mark(1), Inst::CounterReset(0),
        Inst::CheckProgress(1), Inst::LineStart,
        Inst::Split { first: 3, second: 4 }, Inst::Jump(4),
    ] {
        let (mut regexp, _) = direct_loop(3, 0, false, 17);
        regexp.program[3] = replacement;
        assert!(CountedRepeat::at(&regexp, 0).is_none());
    }
    let (regexp, _) = direct_loop(3, 0, false, 17);
    assert!(fixed_body_direction(&regexp, usize::MAX, 2).is_none());
    assert!(fixed_body_direction(&regexp, 2, usize::MAX).is_none());
    assert!(fixed_body_direction(&regexp, 2, 0).is_none());
    for pattern in ["(a[0-9]){17}", "(?:a[0-9]|bc){17}", "(?:a[0-9]?){17}"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!((0..regexp.program.len()).all(|pc| CountedRepeat::at(&regexp, pc).is_none()), "{pattern}");
    }
}

#[test]
fn mixed_atom_eof_and_mismatch_payments_match_individual_dispatch() {
    for width in [2, 3, 7, 31, 32] {
        for rotation in 0..3 {
            for backward in [false, true] {
                let (regexp, word) = direct_loop(width, rotation, backward, 1);
                for length in 0..=width {
                    for mismatch in 0..=width {
                        let mut chars: Vec<_> = word.chars().take(length).collect();
                        // A line terminator rejects Any as well as this class/literal.
                        if mismatch < chars.len() { chars[mismatch] = '\n'; }
                        if backward { chars.reverse(); }
                        let start = if backward { chars.len() } else { 0 };
                        for budget in (1..=width as u64 + 2).chain([u64::MAX]) {
                            let mut remaining = budget - 1;
                            let mut classes = ClassMatches::default();
                            let actual = execute_fixed_body_after_dispatch(
                                &regexp, 2..2 + width, backward, &chars, start,
                                &mut remaining, &mut classes,
                            );
                            let mut expected_remaining = budget;
                            let mut position = start;
                            let mut expected = Ok(Some(position));
                            for instruction in &regexp.program[2..2 + width] {
                                if expected_remaining == 0 {
                                    expected = Err(BacktrackError::StepBudget);
                                    break;
                                }
                                expected_remaining -= 1;
                                let index = if backward { position.checked_sub(1) } else { Some(position) };
                                let accepted = index.and_then(|index| chars.get(index)).is_some_and(|&input| {
                                    match instruction {
                                        Inst::Char { c, .. } => input == *c,
                                        Inst::Class { class, .. } => regexp.class_matches(&regexp.classes[*class], input),
                                        Inst::Any { .. } => !is_line_terminator(input),
                                        _ => unreachable!(),
                                    }
                                });
                                if !accepted {
                                    expected = Ok(None);
                                    break;
                                }
                                position = if backward { position - 1 } else { position + 1 };
                                expected = Ok(Some(position));
                            }
                            assert_eq!(actual, expected, "width={width} rotation={rotation} reverse={backward} length={length} mismatch={mismatch} budget={budget}");
                            assert_eq!(remaining, expected_remaining);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn counted_mixed_refusals_and_caller_floors_match_scalar_execution() {
    for width in [2, 3, 7, 32] {
        for backward in [false, true] {
            for greedy in [false, true] {
                for (minimum, maximum) in [(0, Some(3)), (1, Some(3)), (2, None), (3, Some(3))] {
                    let (mut regexp, word) = direct_loop(width, 0, backward, minimum);
                    let exit = width + 4;
                    regexp.program[0] = Inst::CountedLoop {
                        counter: 0, min: minimum, max: maximum, greedy, body: 1, exit,
                    };
                    regexp.program[exit] = Inst::Char { c: '!', backward };
                    regexp.program.push(Inst::Match);
                    for length in [0, 1, width - 1, width, width + 1, 2 * width - 1, 3 * width, 3 * width + 1] {
                        for marker in [false, true] {
                            let mut chars: Vec<_> = word.repeat(4).chars().take(length).collect();
                            if marker { chars.push('!'); }
                            if backward { chars.reverse(); }
                            let text: String = chars.iter().collect();
                            let input = PreparedInput::new(&text);
                            let start = if backward { input.char_len() } else { 0 };
                            for initial in [0, 1, 4] {
                                for budget in 0..=(width as u64 + 5) * 3 + 3 {
                                    let mut actual = Run::new(&regexp, &input, budget);
                                    let mut reference = Run::new(&regexp, &input, budget);
                                    reference.repetitions_disabled = true;
                                    reference.literal_blocks.disabled = true;
                                    reference.class_matches.disabled = true;
                                    actual.registers = vec![initial, 97];
                                    reference.registers = actual.registers.clone();
                                    let prefix = || vec![
                                        Frame::Alternative { pc: usize::MAX, position: 91 },
                                        Frame::Register { register: 1, old: 1234 },
                                    ];
                                    let mut compact = prefix();
                                    let mut scalar = prefix();
                                    assert_eq!(actual.execute(0, start, &mut compact), reference.execute(0, start, &mut scalar),
                                        "width={width} reverse={backward} greedy={greedy} min={minimum} max={maximum:?} length={length} initial={initial} budget={budget}");
                                    assert_eq!(actual.steps_left, reference.steps_left);
                                    assert_eq!(actual.registers, reference.registers);
                                    assert_eq!(actual.slots, reference.slots);
                                    for stack in [&compact, &scalar] {
                                        assert_eq!(stack.len(), 2);
                                        assert!(matches!(stack[0], Frame::Alternative { pc: usize::MAX, position: 91 }));
                                        assert!(matches!(stack[1], Frame::Register { register: 1, old: 1234 }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn mixed_required_and_optional_histories_do_not_grow_per_iteration() {
    for count in [17, 128, 8192] {
        for minimum in [0, 17] {
            for greedy in [false, true] {
                let lazy = if greedy { "" } else { "?" };
                let regexp = BacktrackRegExp::new(
                    &format!("((?:a[0-9].){{{minimum},{}}}{lazy})!", count + 1), "",
                ).unwrap();
                let input = PreparedInput::new(&format!("{}!", "a7z".repeat(count)));
                let mut actual = Run::new(&regexp, &input, 1_000_000);
                let mut reference = Run::new(&regexp, &input, 1_000_000);
                reference.repetitions_disabled = true;
                reference.literal_blocks.disabled = true;
                reference.class_matches.disabled = true;
                let mut compact = Vec::new();
                let mut scalar = Vec::new();
                assert_eq!(actual.execute_inner(0, 0, &mut compact, 0), reference.execute_inner(0, 0, &mut scalar, 0));
                assert_eq!(actual.steps_left, reference.steps_left);
                assert_eq!(actual.slots, reference.slots);
                assert_eq!(actual.registers, reference.registers);
                let optional = usize::from(!greedy || count > minimum) * 3;
                assert_eq!(compact.len(), 5 + usize::from(minimum != 0) * 2 + optional);
                let choices = if greedy { count - minimum } else { 1 };
                assert_eq!(scalar.len(), 5 + 2 * count + choices);
            }
        }
    }
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    assert_eq!(std::mem::size_of::<Atom>(), 2 * std::mem::size_of::<usize>());
}

#[test]
fn mixed_greedy_retreat_restores_whole_iterations_not_characters() {
    for backward in [false, true] {
        let (mut regexp, _) = direct_loop(3, 0, backward, 1);
        regexp.program[0] = Inst::CountedLoop {
            counter: 0, min: 1, max: Some(5), greedy: true, body: 1, exit: 7,
        };
        let repeat = CountedRepeat::at(&regexp, 0).unwrap();
        let input = PreparedInput::new(if backward { "z7az7az7a" } else { "a7za7za7z" });
        let mut run = Run::new(&regexp, &input, 1000);
        run.registers = vec![1, 97];
        let start = if backward { 9 } else { 0 };
        let mut stack = vec![Frame::Alternative { pc: usize::MAX, position: 71 }];
        assert_eq!(run.execute_counted_greedy(&repeat, 0, start, Some(5), &mut stack).unwrap(), if backward { 0 } else { 9 });
        assert_eq!(stack.len(), 4);
        let work = run.steps_left;
        for iterations in (0..3).rev() {
            let position = if backward { start - iterations * 3 } else { iterations * 3 };
            let frame = stack.pop().unwrap();
            assert_eq!(run.resume_counted_greedy(frame, &mut stack), (7, position));
            assert_eq!(run.registers[0], 1 + iterations);
            assert_eq!(run.registers[1], if iterations == 0 { 97 } else if backward { position + 3 } else { position - 3 });
            assert_eq!(run.steps_left, work);
        }
        assert_eq!(stack.len(), 1);
    }
}

#[test]
fn mixed_unicode_assertions_and_backreferences_keep_node_capture_spans() {
    // Independent Node indices; the native matcher exposes UTF-8 byte spans.
    for (pattern, flags, text, expected) in [
        ("((?:a[0-9].){17,20})a[0-9].(?=!)", "", format!("{}!", "a7z".repeat(20)), vec![Some((0, 60)), Some((0, 57))]),
        ("(?=a)((?:a[0-9].){17,20}?)a[0-9].", "", format!("{}!", "a7z".repeat(20)), vec![Some((0, 54)), Some((0, 51))]),
        ("(?<=((?:a[0-9].){17,20}?))!", "", format!("{}!", "a7z".repeat(20)), vec![Some((60, 61)), Some((9, 60))]),
        ("^((?:a[0-9].){17,20})\\1(?=!)", "", format!("{}!", "a7z".repeat(38)), vec![Some((0, 114)), Some((0, 57))]),
        ("(?<=((?:😀[é].){17,20}?))!", "u", format!("{}!", "😀éz".repeat(20)), vec![Some((140, 141)), Some((21, 140))]),
        ("((?:k[ſ].){17})(?=!)", "iu", format!("{}!", "Ks\n".repeat(17)), Vec::new()),
        ("((?:k[ſ].){17})(?=!)", "isu", format!("{}!", "Ks\n".repeat(17)), vec![Some((0, 85)), Some((0, 85))]),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        let input = PreparedInput::new(&text);
        assert_eq!(regexp.exec_at(&input, 0, false).unwrap(), (!expected.is_empty()).then_some(expected));
        for budget in (0..=192).chain([255, 511, 8192]) {
            compare_search(&regexp, &text, &[0], budget);
        }
    }
}

#[test]
fn mixed_search_reuse_and_disabled_fusion_preserve_the_shared_allowance() {
    for pattern in ["((?:a[0-9].){0,32})(?=!)", "((?:a[0-9].){17,20}?)(?=!)",
        "(?:a[0-9].){17,20}q|((?:a[0-9].){17,20})(?=!)",
        "(?!(?:a[0-9].){17,20}q)((?:a[0-9].){17,20})(?=!)"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let text = format!("{}!{}!", "a7z".repeat(18), "a8y".repeat(19));
        for budget in [0, 1, 63, 127, 255, 511, 4096] {
            compare_search(&regexp, &text, &[0, 55, 0, text.len() + 1], budget);
        }
        let input = PreparedInput::new(&text);
        let mut actual = Run::new(&regexp, &input, 4096);
        let mut reference = Run::new(&regexp, &input, 4096);
        actual.literal_blocks.disabled = true;
        reference.literal_blocks.disabled = true;
        reference.class_matches.disabled = true;
        reference.repetitions_disabled = true;
        assert_eq!(actual.search(0, true), reference.search(0, true));
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
    }
}

#[test]
fn lazy_mixed_zero_exit_and_maximum_keep_original_register_ownership() {
    let (mut regexp, _) = direct_loop(3, 0, false, 0);
    regexp.program[0] = Inst::CountedLoop {
        counter: 0, min: 0, max: Some(20), greedy: false, body: 1, exit: 7,
    };
    let input = PreparedInput::new("a7za8y");
    let mut run = Run::new(&regexp, &input, 2);
    run.registers[1] = 97;
    assert_eq!(run.execute(0, 0, &mut Vec::new()).unwrap(), Some(0));
    assert_eq!(run.steps_left, 0);
    assert_eq!(run.registers, [0, 97]);
    for backward in [false, true] {
        let (mut regexp, _) = direct_loop(3, 0, backward, 0);
        regexp.program[0] = Inst::CountedLoop {
            counter: 0, min: 0, max: Some(3), greedy: false, body: 1, exit: 7,
        };
        let input = PreparedInput::new(if backward { "y8az7a" } else { "a7za8y" });
        let repeat = CountedRepeat::at(&regexp, 0).unwrap();
        let mut run = Run::new(&regexp, &input, 1000);
        run.registers = vec![1, 97];
        let start = if backward { 6 } else { 0 };
        let mut stack = vec![Frame::Alternative { pc: usize::MAX, position: 19 }];
        run.push_counted_lazy(&repeat, 0, start, &mut stack);
        for iteration in 1..=2 {
            let frame = stack.pop().unwrap();
            let position = if backward { start - iteration * 3 } else { iteration * 3 };
            assert_eq!(run.resume_counted_lazy(frame, &mut stack).unwrap(), Some((7, position)));
            assert_eq!(run.registers[0], 1 + iteration);
            assert_eq!(stack.len(), if iteration == 1 { 4 } else { 3 });
        }
        assert!(matches!(stack[1], Frame::Register { register: 1, old: 97 }));
        assert!(matches!(stack[2], Frame::Register { register: 0, old: 1 }));
    }
}
