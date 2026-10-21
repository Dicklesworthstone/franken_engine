//! Optional counted captures retain complete-body exits and original state.

use super::super::PreparedInput;
use super::*;

fn direct_loop(
    groups: usize,
    width: usize,
    minimum: usize,
    maximum: Option<usize>,
    backward: bool,
) -> BacktrackRegExp {
    let mut regexp = BacktrackRegExp::new("((ab)){0,32}!", "").unwrap();
    regexp.group_count = groups + 1;
    regexp.registers = 2;
    let exit = width + 2 * groups + 5;
    regexp.program = vec![
        Inst::CountedLoop {
            counter: 0, min: minimum, max: maximum, greedy: true, body: 1, exit,
        },
        Inst::Mark(1),
        Inst::Clear { from: 2, to: 2 + 2 * groups },
    ];
    for group in 1..=groups {
        regexp.program.push(Inst::Save(2 * group + usize::from(backward)));
    }
    regexp.program.extend((0..width).map(|index| Inst::Char {
        c: char::from(b'a' + (index % 3) as u8), backward,
    }));
    for group in (1..=groups).rev() {
        regexp.program.push(Inst::Save(2 * group + usize::from(!backward)));
    }
    regexp.program.extend([
        Inst::CounterStep { counter: 0, mark: 1, min: minimum },
        Inst::Jump(0),
        Inst::Char { c: '!', backward },
        Inst::Match,
    ]);
    regexp
}

#[test]
fn optional_capture_greedy_refusals_and_whole_body_retreats_match_scalar_execution() {
    for groups in [1, 2, 8] {
        for width in [1, 2, 32] {
            for backward in [false, true] {
                for minimum in [0, 2] {
                    for maximum in [Some(minimum + 1), Some(minimum + 3), None] {
                        let regexp = direct_loop(groups, width, minimum, maximum, backward);
                        for initial in [0, 1, 5] {
                            for length in [0, width - 1, 3 * width, 3 * width + 1] {
                                let mut chars: Vec<_> = (0..length)
                                    .map(|i| char::from(b'a' + (i % width % 3) as u8)).collect();
                                if length > 3 * width { chars[length - 1] = '!'; }
                                if backward { chars.reverse(); }
                                let input = PreparedInput::new(&chars.iter().collect::<String>());
                                let start = if backward { length } else { 0 };
                                for budget in 0..=(3 * (width + 4 * groups + 5) + 2) as u64 {
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
                                        "g={groups} w={width} back={backward} min={minimum} max={maximum:?} initial={initial} n={length} budget={budget}");
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
}

#[test]
fn counted_capture_ranges_restore_iteration_counts_not_character_distances() {
    for backward in [false, true] {
        let regexp = direct_loop(2, 2, 0, None, backward);
        let input = PreparedInput::new(if backward { "bababa" } else { "ababab" });
        let mut run = Run::new(&regexp, &input, 1000);
        run.registers = vec![5, 97];
        run.slots = vec![Some(11), None, Some(23), Some(29), None, Some(31)];
        let original_slots = run.slots.clone();
        let repeat = CapturedCounted::at(&regexp, 0, &mut run.literal_blocks).unwrap();
        let (start, end) = if backward { (6, 0) } else { (0, 6) };
        let mut stack = vec![Frame::Alternative { pc: usize::MAX, position: 13 }];
        run.steps_left -= 1; // CountedLoop was paid by dispatch.
        assert_eq!(run.execute_captured_counted_greedy(&repeat, 0, start, &mut stack).unwrap(), end);
        assert_eq!(run.registers[0], 8);
        assert_eq!(stack.len(), 8, "caller plus six original values and one range");
        for iterations in (0..3).rev() {
            let position = if backward { start - 2 * iterations } else { 2 * iterations };
            let frame = stack.pop().unwrap();
            assert_eq!(run.resume_captured_counted_greedy(frame, &mut stack), (repeat.body.exit, position));
            assert_eq!(run.registers[0], 5 + iterations);
            if iterations == 0 {
                assert_eq!(run.slots, original_slots);
                assert_eq!(run.registers[1], 97);
            } else {
                let previous = repeat.body.previous(position);
                let span = if backward { [Some(position), Some(previous)] }
                    else { [Some(previous), Some(position)] };
                assert_eq!(&run.slots[2..4], &span);
                assert_eq!(&run.slots[4..6], &span);
                assert_eq!(run.registers[1], previous);
            }
        }
        assert_eq!(stack.len(), 1);
        assert!(matches!(stack[0], Frame::Alternative { pc: usize::MAX, position: 13 }));
    }
}

#[test]
fn optional_counted_capture_storage_is_independent_of_iteration_count() {
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    for count in [17, 128, 8192] {
        for minimum in [0, 3] {
            let pattern = format!("((ab)){{{minimum},{count}}}");
            let regexp = BacktrackRegExp::new(&pattern, "").unwrap();
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
            assert_eq!(compact.len(), if minimum == 0 { 10 } else { 16 });
            assert_eq!(scalar.len(), 11 * count - minimum - 1);
        }
    }
}

#[test]
fn optional_capture_failure_restores_both_required_and_optional_histories() {
    for minimum in [0, 2] {
        let regexp = direct_loop(2, 2, minimum, Some(5), false);
        let input = PreparedInput::new("abababab?");
        let mut run = Run::new(&regexp, &input, 10_000);
        run.registers = vec![0, 97];
        run.slots = vec![Some(11), None, Some(23), Some(29), None, Some(31)];
        let original_slots = run.slots.clone();
        assert_eq!(run.execute(0, 0, &mut Vec::new()), Ok(None));
        assert_eq!(run.slots, original_slots);
        assert_eq!(run.registers, vec![0, 97]);
    }
}

#[test]
fn optional_capture_searches_preserve_shared_work_and_assertion_journals() {
    for (pattern, flags) in [
        ("((ab)){0,32}ab(?=!)", ""), ("((ab)){17,20}\\2!", ""),
        ("((ab)){17,}(?=!)", ""), ("(?=((ab)){0,32})z|ab", ""),
        ("(?!(ab){17,20}!)ab", ""), ("(?<=((ab)){0,32})!", ""),
        ("(?<!((ab)){17,20})!", ""), ("((kſ)){0,32}(?=!)", "iu"),
        ("((😀é)){0,32}(?=!)", "u"), ("(([a-c])){17,20}(?=!)", "i"),
        ("((.)){0,32}(?=!)", "s"), ("((.)){0,32}(?=!)", ""),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        for text in [String::new(), "abab!xxab!".into(), "ab".repeat(16),
            format!("{}!", "ab".repeat(21)), "Ksks!".into(), "😀é😀é!".into(), "a\nb!".into()] {
            let input = PreparedInput::new(&text);
            for budget in (0..=96).chain([127, 255, 511, 4096]) {
                let mut actual = Run::new(&regexp, &input, budget);
                let mut reference = Run::new(&regexp, &input, budget);
                reference.repetitions_disabled = true;
                reference.literal_blocks.disabled = true;
                reference.class_matches.disabled = true;
                for (start, sticky) in [(0, false), (1, true), (input.char_len(), false),
                    (input.char_len() + 1, false), (0, true)] {
                    assert_eq!(actual.search(start, sticky), reference.search(start, sticky), "{pattern}");
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
