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
    for pattern in ["(?:ab){17}", "(?:abc){18}?", "((?:abcd){17})", "(?<=(?:ab){17})x"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!((0..regexp.program.len()).any(|pc| {
            CountedRepeat::at(&regexp, pc).is_some_and(|repeat| repeat.width > 1)
        }), "{pattern}");
    }
    for pattern in ["(ab){17}", "(?:ab|cd){17}", "(?:ab?){17}", "(?:a[bc]){17}", "(?:a.){17}"] {
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
