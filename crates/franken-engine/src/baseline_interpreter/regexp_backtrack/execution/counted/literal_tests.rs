//! Differential tests execute the production bytecode with fusion enabled
//! and disabled. The reference also disables literal superinstructions.
use super::super::PreparedInput;
use super::*;

fn compare(regexp: &BacktrackRegExp, text: &str, start: usize, budget: u64) {
    let input = PreparedInput::new(text);
    let mut actual = Run::new(regexp, &input, budget);
    let mut reference = Run::new(regexp, &input, budget);
    reference.repetitions_disabled = true;
    reference.literal_blocks.disabled = true;
    assert_eq!(actual.search(start, true), reference.search(start, true));
    assert_eq!(actual.steps_left, reference.steps_left, "instruction allowance");
    assert_eq!(actual.slots, reference.slots, "including partial refusal captures");
    assert_eq!(actual.registers, reference.registers, "including partial refusal registers");
    assert!(actual.stack.is_empty());
    assert!(actual.capture_seen.iter().all(|seen| !seen));
}

fn direct_loop(width: usize, backward: bool, minimum: usize) -> BacktrackRegExp {
    let mut regexp = BacktrackRegExp::new("a{17}", "").unwrap();
    regexp.registers = 2;
    let exit = width + 4;
    regexp.program = vec![
        Inst::CountedLoop {
            counter: 0, min: minimum, max: Some(minimum),
            greedy: true, body: 1, exit,
        },
        Inst::Mark(1),
    ];
    regexp.program.extend((0..width).map(|index| Inst::Char {
        c: char::from(b'a' + (index % 3) as u8), backward,
    }));
    regexp.program.extend([
        Inst::CounterStep { counter: 0, mark: 1, min: minimum },
        Inst::Jump(0),
        Inst::Match,
    ]);
    regexp
}

#[test]
fn counted_literal_recognition_requires_the_complete_bounded_body() {
    for width in [2, 3, 31, 32, 33, 64] {
        let regexp = direct_loop(width, false, 17);
        assert_eq!(CountedRepeat::at(&regexp, 0).is_some(), width <= LITERAL_WIDTH);
    }
    for pattern in ["(?:ab){17}", "(?:abc){18}?", "((?:abcd){17})", "(?<=(?:ab){17})x",
        "(?:ab){17,20}", "(?:ab){17,20}?", "(?:abc){0,32}?", "(?:ab){17,}",
        "(?<=(?:ab){17,20}?)x", "(?:a[bc]){17}", "(?:a.){17}"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!((0..regexp.program.len()).any(|pc| {
            CountedRepeat::at(&regexp, pc).is_some_and(|repeat| repeat.width > 1)
        }), "{pattern}");
    }
    for pattern in ["(ab){17}", "(?:ab|cd){17}", "(?:ab?){17}"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!((0..regexp.program.len()).all(|pc| CountedRepeat::at(&regexp, pc).is_none()), "{pattern}");
    }
    for mutation in 0..7 {
        let mut regexp = direct_loop(3, false, 17);
        match mutation {
            0 => regexp.program[3] = Inst::Char { c: 'b', backward: true },
            1 => regexp.program[3] = Inst::Save(0),
            2 => regexp.program[5] = Inst::CounterStep { counter: 1, mark: 1, min: 17 },
            3 => regexp.program[5] = Inst::CounterStep { counter: 0, mark: 1, min: 18 },
            4 => regexp.program[6] = Inst::Jump(1),
            5 => regexp.registers = 1,
            _ => regexp.program[0] = Inst::CountedLoop {
                counter: 0, min: 17, max: Some(17), greedy: true, body: 2, exit: 7,
            },
        }
        assert!(CountedRepeat::at(&regexp, 0).is_none(), "mutation={mutation}");
    }
    assert!(CountedRepeat::at(&direct_loop(2, false, 17), usize::MAX).is_none());
}

#[test]
fn required_literal_mismatches_and_refusals_keep_each_paid_register_write() {
    for width in [2, 3, 7, 31, 32] {
        let word: String = (0..width).map(|i| char::from(b'a' + (i % 3) as u8)).collect();
        for backward in [false, true] {
            let regexp = direct_loop(width, backward, 3);
            // Include partial bodies, every mismatch position and a full match.
            for length in 0..=width * 3 {
                for mismatch in [false, true] {
                    let mut chars: Vec<_> = word.repeat(3).chars().take(length).collect();
                    if mismatch { chars.push('!'); }
                    if backward { chars.reverse(); }
                    let text: String = chars.iter().collect();
                    let input = PreparedInput::new(&text);
                    let start = if backward { input.char_len() } else { 0 };
                    for initial in [0, 1, 3, 5] {
                        for budget in 0..=(width as u64 + 4) * 3 + 2 {
                            let mut actual = Run::new(&regexp, &input, budget);
                            let mut reference = Run::new(&regexp, &input, budget);
                            reference.repetitions_disabled = true;
                            reference.literal_blocks.disabled = true;
                            actual.registers = vec![initial, 97];
                            reference.registers = actual.registers.clone();
                            assert_eq!(actual.execute(0, start, &mut Vec::new()),
                                reference.execute(0, start, &mut Vec::new()),
                                "width={width} reverse={backward} length={length} initial={initial} budget={budget}");
                            assert_eq!(actual.steps_left, reference.steps_left);
                            assert_eq!(actual.registers, reference.registers);
                            assert_eq!(actual.slots, reference.slots);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn required_literals_preserve_case_folding_assertions_backreferences_and_alternatives() {
    for (pattern, flags, text, start) in [
        ("((?:ab){17})\\1", "", "ab".repeat(34), 0),
        ("(?=((?:ab){17}))(?:ab){17}x", "", format!("{}x", "ab".repeat(17)), 0),
        ("(?!(?:ab){17}z)(?:ab){17}x", "", format!("{}x", "ab".repeat(17)), 0),
        ("(?:ab){17}z|((?:ab){17}x)", "", format!("{}x", "ab".repeat(17)), 0),
        ("(?<=((?:ab){17}))x", "", format!("{}x", "ab".repeat(17)), 34),
        ("((?:kſ){17})(?=!)", "iu", format!("{}!", "Ks".repeat(17)), 0),
        ("((?:kſ){17})(?=!)", "i", format!("{}!", "Ks".repeat(17)), 0),
        ("(?<=((?:😀é){17}))x", "u", format!("{}x", "😀é".repeat(17)), 34),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        for budget in (0..=160).chain([255, 511, 4096]) {
            compare(&regexp, &text, start, budget);
        }
    }
}

#[test]
fn large_fixed_literal_counts_retain_two_undos_not_one_pair_per_iteration() {
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    for count in [17, 128, 8192] {
        let regexp = BacktrackRegExp::new(&format!("((?:abcd){{{count}}})"), "").unwrap();
        let input = PreparedInput::new(&"abcd".repeat(count));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.repetitions_disabled = true;
        reference.literal_blocks.disabled = true;
        let mut compact = Vec::new();
        let mut scalar = Vec::new();
        assert_eq!(actual.execute_inner(0, 0, &mut compact, 0), reference.execute_inner(0, 0, &mut scalar, 0));
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(compact.len(), 7, "four captures, counter reset and two mandatory undos");
        assert_eq!(scalar.len(), 5 + 2 * count);
    }
}

#[test]
fn disabling_literal_blocks_keeps_a_real_scalar_fallback() {
    let regexp = BacktrackRegExp::new("((?:ab){17})(?=!)", "").unwrap();
    let input = PreparedInput::new(&format!("{}!", "ab".repeat(17)));
    let mut actual = Run::new(&regexp, &input, 1024);
    actual.literal_blocks.disabled = true;
    let mut reference = Run::new(&regexp, &input, 1024);
    reference.literal_blocks.disabled = true;
    reference.repetitions_disabled = true;
    assert_eq!(actual.search(0, true), reference.search(0, true));
    assert_eq!(actual.steps_left, reference.steps_left);
    assert_eq!(actual.slots, reference.slots);
    assert_eq!(actual.registers, reference.registers);
    assert_eq!(actual.literal_dispatches, reference.literal_dispatches);
}

#[test]
fn required_literal_searches_share_allowance_after_success_and_refusal() {
    let regexp = BacktrackRegExp::new("((?:ab){17})(?=!)", "").unwrap();
    let input = PreparedInput::new(&format!("{}!{}!", "ab".repeat(17), "ab".repeat(17)));
    for budget in [0, 1, 102, 103, 110, 256, 1024] {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.repetitions_disabled = true;
        reference.literal_blocks.disabled = true;
        for start in [0, 35, 0, input.char_len() + 1] {
            assert_eq!(actual.search(start, false), reference.search(start, false));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert!(actual.stack.is_empty());
        }
    }
}

#[test]
fn optional_literal_exits_keep_scalar_state_at_every_small_budget() {
    for width in [2, 3, 7, 32] {
        let word: String = (0..width).map(|i| char::from(b'a' + (i % 3) as u8)).collect();
        for backward in [false, true] {
            for greedy in [false, true] {
                for (minimum, maximum) in [(0, Some(4)), (2, Some(4)), (2, None)] {
                    let mut regexp = direct_loop(width, backward, minimum);
                    let exit = width + 4;
                    regexp.program[0] = Inst::CountedLoop {
                        counter: 0, min: minimum, max: maximum, greedy, body: 1, exit,
                    };
                    // Each exit must match a marker, so both greedy retreat
                    // and lazy growth run through failed continuations.
                    regexp.program[exit] = Inst::Char { c: '!', backward };
                    regexp.program.push(Inst::Match);
                    for length in 0..=width * 3 + 1 {
                        for marker in [false, true] {
                            let mut text: Vec<_> = word.repeat(4).chars().take(length).collect();
                            if marker { text.push('!'); }
                            if backward { text.reverse(); }
                            let text: String = text.iter().collect();
                            let input = PreparedInput::new(&text);
                            let start = if backward { input.char_len() } else { 0 };
                            for initial in [0, 1, 3, 7] {
                                for budget in 0..=(width as u64 + 5) * 3 + 3 {
                                    let mut actual = Run::new(&regexp, &input, budget);
                                    let mut reference = Run::new(&regexp, &input, budget);
                                    reference.repetitions_disabled = true;
                                    reference.literal_blocks.disabled = true;
                                    actual.registers = vec![initial, 97];
                                    reference.registers = actual.registers.clone();
                                    let prefix = || vec![
                                        Frame::Alternative { pc: usize::MAX, position: 91 },
                                        Frame::Register { register: 1, old: 1234 },
                                    ];
                                    let mut compact = prefix();
                                    let mut scalar = prefix();
                                    assert_eq!(actual.execute(0, start, &mut compact),
                                        reference.execute(0, start, &mut scalar),
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
fn greedy_literal_ranges_restore_iterations_not_character_counts() {
    for backward in [false, true] {
        let mut regexp = direct_loop(3, backward, 1);
        regexp.program[0] = Inst::CountedLoop {
            counter: 0, min: 1, max: Some(5), greedy: true, body: 1, exit: 7,
        };
        let repeat = CountedRepeat::at(&regexp, 0).unwrap();
        let input = PreparedInput::new(if backward { "cbacbacba" } else { "abcabcabc" });
        let mut run = Run::new(&regexp, &input, 1000);
        // A preceding mandatory iteration already ran, and its undo belongs
        // to the caller. Only the optional suffix is summarized here.
        run.registers = vec![1, 97];
        let mut stack = vec![Frame::Alternative { pc: usize::MAX, position: 71 }];
        let start = if backward { 9 } else { 0 };
        let end = if backward { 0 } else { 9 };
        assert_eq!(run.execute_counted_greedy(&repeat, 0, start, Some(5), &mut stack).unwrap(), end);
        assert_eq!(run.registers[0], 4);
        assert_eq!(stack.len(), 4, "caller plus two undos and one range");
        let work = run.steps_left;
        for iterations in (0..3).rev() {
            let position = if backward { start - iterations * 3 } else { iterations * 3 };
            let frame = stack.pop().unwrap();
            assert_eq!(run.resume_counted_greedy(frame, &mut stack), (7, position));
            assert_eq!(run.registers[0], 1 + iterations);
            assert_eq!(run.registers[1], if iterations == 0 { 97 } else if backward {
                position + 3
            } else { position - 3 });
            assert_eq!(run.steps_left, work, "resuming an already-paid exit costs no new work");
        }
        assert_eq!(stack.len(), 1);
        assert!(matches!(stack[0], Frame::Alternative { pc: usize::MAX, position: 71 }));
    }
}

#[test]
fn lazy_literal_maximum_keeps_original_register_undos_for_failed_tail() {
    for backward in [false, true] {
        let mut regexp = direct_loop(3, backward, 0);
        regexp.program[0] = Inst::CountedLoop {
            counter: 0, min: 0, max: Some(3), greedy: false, body: 1, exit: 7,
        };
        let input = PreparedInput::new(if backward { "cbacba" } else { "abcabc" });
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
        // At max there is no further extension, but tail failure must still
        // restore BOTH original registers before reaching the caller's floor.
        assert!(matches!(stack[1], Frame::Register { register: 1, old: 97 }));
        assert!(matches!(stack[2], Frame::Register { register: 0, old: 1 }));
        while stack.len() > 1 {
            let Frame::Register { register, old } = stack.pop().unwrap() else {
                panic!("only paired undos remain at the maximum");
            };
            run.registers[register] = old;
        }
        assert_eq!(run.registers, [1, 97]);
        assert!(matches!(stack[0], Frame::Alternative { pc: usize::MAX, position: 19 }));
    }
    // No Mark or Char can run: this budget pays only CountedLoop and Match.
    let mut regexp = direct_loop(3, false, 0);
    regexp.program[0] = Inst::CountedLoop {
        counter: 0, min: 0, max: Some(20), greedy: false, body: 1, exit: 7,
    };
    let input = PreparedInput::new("abcabcabc");
    let mut run = Run::new(&regexp, &input, 2);
    run.registers[1] = 97;
    assert_eq!(run.execute(0, 0, &mut Vec::new()).unwrap(), Some(0));
    assert_eq!(run.steps_left, 0);
    assert_eq!(run.registers, [0, 97]);
}

#[test]
fn optional_literal_choices_stay_constant_size_with_and_without_a_required_prefix() {
    for count in [17, 128, 8192] {
        for minimum in [0, 17] {
            for greedy in [false, true] {
                let lazy = if greedy { "" } else { "?" };
                let pattern = format!("((?:abcd){{{minimum},{}}}{lazy})!", count + 1);
                let regexp = BacktrackRegExp::new(&pattern, "").unwrap();
                let input = PreparedInput::new(&format!("{}!", "abcd".repeat(count)));
                let mut actual = Run::new(&regexp, &input, 1_000_000);
                let mut reference = Run::new(&regexp, &input, 1_000_000);
                reference.repetitions_disabled = true;
                reference.literal_blocks.disabled = true;
                let mut compact = Vec::new();
                let mut scalar = Vec::new();
                assert_eq!(actual.execute_inner(0, 0, &mut compact, 0),
                    reference.execute_inner(0, 0, &mut scalar, 0));
                assert_eq!(actual.steps_left, reference.steps_left);
                assert_eq!(actual.slots, reference.slots);
                assert_eq!(actual.registers, reference.registers);
                // Greedy contributes no optional history when it matched
                // exactly the mandatory count. Lazy still owns its next try.
                let optional = usize::from(!greedy || count > minimum) * 3;
                assert_eq!(compact.len(), 5 + usize::from(minimum != 0) * 2 + optional);
                let choices = if greedy { count - minimum } else { 1 };
                assert_eq!(scalar.len(), 5 + 2 * count + choices);
            }
        }
    }
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
}

#[test]
fn optional_literal_captures_match_live_node_reference_spans() {
    // Live Node v22.16.0 / V8 indices, converted from UTF-16 to byte spans.
    // Assertions/backreferences force these programs onto the native matcher.
    let cases = vec![
        ("((?:ab){17,20})ab(?=!)", "", format!("{}!", "ab".repeat(20)),
            vec![Some((0_usize, 40_usize)), Some((0, 38))]),
        ("(?=a)((?:ab){17,20}?)ab", "", format!("{}!", "ab".repeat(20)),
            vec![Some((0, 36)), Some((0, 34))]),
        ("(?<=((?:ab){17,20}))!", "", format!("{}!", "ab".repeat(20)),
            vec![Some((40, 41)), Some((0, 40))]),
        ("(?<=((?:ab){17,20}?))!", "", format!("{}!", "ab".repeat(20)),
            vec![Some((40, 41)), Some((6, 40))]),
        ("^(?:(?:ab){17,20}z|((?:ab){17,20}))(?=!)", "", format!("{}!", "ab".repeat(19)),
            vec![Some((0, 38)), Some((0, 38))]),
        ("^((?:ab){17,20})\\1(?=!)", "", format!("{}!", "ab".repeat(38)),
            vec![Some((0, 76)), Some((0, 38))]),
        ("(?<=((?:😀é){17,20}?))!", "u", format!("{}!", "😀é".repeat(20)),
            vec![Some((120, 121)), Some((18, 120))]),
    ];
    for (pattern, flags, text, expected) in cases {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        let input = PreparedInput::new(&text);
        assert_eq!(regexp.exec_at(&input, 0, false).unwrap(), Some(expected));
        for budget in (0..=255).chain([511, 4096]) {
            compare(&regexp, &text, 0, budget);
        }
    }
}

#[test]
fn optional_literal_reuse_does_not_renew_work_or_retain_an_earlier_choice() {
    for greedy in [false, true] {
        let lazy = if greedy { "" } else { "?" };
        let pattern = format!("((?:ab){{0,32}}{lazy})(?:cd){{17,20}}(?=!)");
        let regexp = BacktrackRegExp::new(&pattern, "").unwrap();
        let text = format!("{}{}!{}{}!", "ab".repeat(3), "cd".repeat(18),
            "ab".repeat(2), "cd".repeat(19));
        let input = PreparedInput::new(&text);
        for budget in [0, 1, 63, 127, 255, 511, 1024] {
            let mut actual = Run::new(&regexp, &input, budget);
            let mut reference = Run::new(&regexp, &input, budget);
            reference.repetitions_disabled = true;
            reference.literal_blocks.disabled = true;
            for start in [0, 43, 0, input.char_len() + 1] {
                assert_eq!(actual.search(start, false), reference.search(start, false));
                assert_eq!(actual.steps_left, reference.steps_left);
                assert_eq!(actual.slots, reference.slots);
                assert_eq!(actual.registers, reference.registers);
                assert!(actual.stack.is_empty());
            }
        }
    }
}