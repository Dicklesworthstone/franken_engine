//! Counted captures use the real VM as their scalar differential oracle.

use super::*;
use super::super::PreparedInput;

fn direct_loop(groups: usize, width: usize, minimum: usize, backward: bool) -> BacktrackRegExp {
    let mut regexp = BacktrackRegExp::new("((ab)){17}", "").unwrap();
    regexp.group_count = groups + 1;
    regexp.registers = 2;
    let exit = width + 2 * groups + 5;
    regexp.program = vec![
        Inst::CountedLoop { counter: 0, min: minimum, max: Some(minimum),
            greedy: true, body: 1, exit },
        Inst::Mark(1), Inst::Clear { from: 2, to: 2 + 2 * groups },
    ];
    for group in 1..=groups {
        regexp.program.push(Inst::Save(2 * group + usize::from(backward)));
    }
    regexp.program.extend((0..width).map(|i| Inst::Char {
        c: char::from(b'a' + (i % 3) as u8), backward,
    }));
    for group in (1..=groups).rev() {
        regexp.program.push(Inst::Save(2 * group + usize::from(!backward)));
    }
    regexp.program.extend([
        Inst::CounterStep { counter: 0, mark: 1, min: minimum },
        Inst::Jump(0), Inst::Match,
    ]);
    regexp
}

#[test]
fn counted_capture_recognition_requires_complete_fixed_width_groups() {
    for pattern in ["(a){17}", "((ab)){17}?", "([a-z]){20}", "(.){17}",
        "(?<=((ab)){17})x", "(?<word>abc){32}"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert!((0..regexp.program.len()).any(|pc|
            CapturedCounted::at(&regexp, pc, &mut blocks).is_some()), "{pattern}");
    }
    for pattern in ["(a){17,18}", "(a){17,}", "(a|b){17}", "(a?){17}",
        "((a)b){17}", "(?:(a)(b)){17}", "(a[bc]){17}", "(?:ab){17}",
        "(a)*", "(a)*?", "(a){16}", "(((((((((a))))))))){17}"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert!((0..regexp.program.len()).all(|pc|
            CapturedCounted::at(&regexp, pc, &mut blocks).is_none()), "{pattern}");
    }
    for width in [1, 2, 31, 32, 33] {
        let regexp = BacktrackRegExp::new(&format!("({}){{17}}", "a".repeat(width)), "").unwrap();
        let mut blocks = LiteralBlocks::default();
        assert_eq!((0..regexp.program.len()).any(|pc|
            CapturedCounted::at(&regexp, pc, &mut blocks).is_some()), width <= 32);
    }
}

#[test]
fn counted_captures_preserve_each_paid_write_and_the_callers_stack_floor() {
    for groups in [1, 2, 8] {
        for width in [1, 2, 32] {
            for backward in [false, true] {
                for minimum in [0, 1, 3] {
                    let regexp = direct_loop(groups, width, minimum, backward);
                    for initial in [0, 1, 4] {
                        for length in [0, width - 1, 3 * width, 3 * width + 1] {
                            let mut text: Vec<_> = (0..length)
                                .map(|i| char::from(b'a' + (i % width % 3) as u8)).collect();
                            if length > 3 * width { text[length - 1] = '!'; }
                            if backward { text.reverse(); }
                            let input = PreparedInput::new(&text.iter().collect::<String>());
                            let start = if backward { length } else { 0 };
                            for budget in 0..=(2 * (width + 4 * groups + 5)) as u64 {
                                let mut actual = Run::new(&regexp, &input, budget);
                                let mut reference = Run::new(&regexp, &input, budget);
                                reference.repetitions_disabled = true;
                                reference.literal_blocks.disabled = true;
                                for run in [&mut actual, &mut reference] {
                                    run.registers = vec![initial, 97];
                                    for (slot, value) in run.slots.iter_mut().enumerate() {
                                        *value = (slot % 3 != 0).then_some(100 + slot);
                                    }
                                }
                                let prefix = || vec![
                                    Frame::Alternative { pc: usize::MAX, position: 13 },
                                    Frame::Slot { slot: 0, old: Some(777) },
                                ];
                                let mut compact = prefix();
                                let mut scalar = prefix();
                                assert_eq!(actual.execute(0, start, &mut compact),
                                    reference.execute(0, start, &mut scalar));
                                assert_eq!(actual.steps_left, reference.steps_left);
                                assert_eq!(actual.slots, reference.slots,
                                    "g={groups} w={width} back={backward} min={minimum} initial={initial} n={length} budget={budget}");
                                assert_eq!(actual.registers, reference.registers);
                                for stack in [&compact, &scalar] {
                                    assert_eq!(stack.len(), 2);
                                    assert!(matches!(stack[0], Frame::Alternative { pc: usize::MAX, position: 13 }));
                                    assert!(matches!(stack[1], Frame::Slot { slot: 0, old: Some(777) }));
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
fn fixed_count_captures_keep_bounded_history_and_exact_work() {
    for count in [17, 128, 8192] {
        let regexp = BacktrackRegExp::new(&format!("((ab)){{{count}}}"), "").unwrap();
        let input = PreparedInput::new(&"ab".repeat(count));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.repetitions_disabled = true;
        let mut compact = Vec::new();
        let mut scalar = Vec::new();
        assert_eq!(actual.execute_inner(0, 0, &mut compact, 0),
            reference.execute_inner(0, 0, &mut scalar, 0));
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(compact.len(), 9, "whole-match slots, reset, two registers and four captures");
        assert_eq!(scalar.len(), 10 * count - 1);
    }
}

#[test]
fn fixed_counts_share_original_budgets_across_searches_assertions_and_failures() {
    for (pattern, flags) in [
        ("((ab)){17}(?=!)", ""), ("((ab)){17}\\2!", ""),
        ("(?=((ab)){17})z|ab", ""), ("(?!(ab){17}!)ab", ""),
        ("(?<=((ab)){17})!", ""), ("(?<!((ab)){17})!", ""),
        ("((kſ)){17}(?=!)", "iu"), ("((😀é)){17}(?=!)", "u"),
        ("(([a-c])){17}(?=!)", "i"), ("((.)){17}(?=!)", "s"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        for text in [String::new(), "ab".repeat(16), format!("{}!", "ab".repeat(18)),
            format!("{}!", "Ks".repeat(17)), format!("{}!", "😀é".repeat(17))] {
            let input = PreparedInput::new(&text);
            for budget in (0..=96).chain([127, 255, 511, 4096]) {
                let mut actual = Run::new(&regexp, &input, budget);
                let mut reference = Run::new(&regexp, &input, budget);
                reference.repetitions_disabled = true;
                reference.literal_blocks.disabled = true;
                reference.class_matches.disabled = true;
                for (start, sticky) in [(0, false), (1, true), (input.char_len(), false),
                    (input.char_len() + 1, false), (0, true)] {
                    assert_eq!(actual.search(start, sticky), reference.search(start, sticky));
                    assert_eq!(actual.steps_left, reference.steps_left);
                    assert_eq!(actual.slots, reference.slots);
                    assert_eq!(actual.registers, reference.registers);
                    assert!(actual.stack.is_empty());
                    assert!(actual.capture_seen.iter().all(|seen| !seen));
                }
            }
        }
    }
}

#[test]
fn counted_capture_recognition_rejects_mismatched_registers_and_tail_instructions() {
    for kind in 0..7 {
        let mut regexp = direct_loop(2, 2, 17, false);
        match kind {
            0 => regexp.program[9] = Inst::CounterStep { counter: 1, mark: 1, min: 17 },
            1 => regexp.program[9] = Inst::CounterStep { counter: 0, mark: 0, min: 17 },
            2 => regexp.program[9] = Inst::CounterStep { counter: 0, mark: 1, min: 18 },
            3 => regexp.program[10] = Inst::Jump(1),
            4 => regexp.program[4] = Inst::Save(2),
            5 => regexp.program[2] = Inst::Clear { from: 1, to: 6 },
            _ => regexp.registers = 1,
        }
        assert!(CapturedCounted::at(&regexp, 0, &mut LiteralBlocks::default()).is_none(), "kind={kind}");
    }
    let regexp = direct_loop(1, 1, 17, false);
    assert!(CapturedCounted::at(&regexp, usize::MAX, &mut LiteralBlocks::default()).is_none());
}

#[test]
fn fixed_count_failure_restores_original_nonempty_capture_values() {
    let regexp = direct_loop(2, 2, 3, false);
    let input = PreparedInput::new("ababax");
    let mut run = Run::new(&regexp, &input, 1000);
    run.slots = vec![Some(11), None, Some(23), Some(29), None, Some(31)];
    run.registers = vec![0, 97];
    let slots = run.slots.clone();
    let registers = run.registers.clone();
    assert_eq!(run.execute(0, 0, &mut Vec::new()), Ok(None));
    assert_eq!(run.slots, slots);
    assert_eq!(run.registers, registers);
}
