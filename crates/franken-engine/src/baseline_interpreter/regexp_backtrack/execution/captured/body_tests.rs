//! Affordable-body batching versus the retained precise production path.

use super::super::PreparedInput;
use super::*;

fn capture_body(regexp: &BacktrackRegExp) -> CapturedRepeat {
    let mut blocks = LiteralBlocks::default();
    (0..regexp.program.len())
        .find_map(|pc| CapturedRepeat::at(regexp, pc, &mut blocks))
        .expect("fixture contains a complete captured repetition")
}

fn compare_body(regexp: &BacktrackRegExp, text: &str, position: usize, budget: u64) {
    let repeat = capture_body(regexp);
    let input = PreparedInput::new(text);
    let mut actual = Run::new(regexp, &input, budget);
    let mut precise = Run::new(regexp, &input, budget);
    for run in [&mut actual, &mut precise] {
        run.registers.fill(97);
        for (slot, value) in run.slots.iter_mut().enumerate() {
            *value = (slot % 3 != 0).then_some(100 + slot);
        }
    }
    assert_eq!(
        actual.advance_captured_iteration(&repeat, position),
        precise.advance_captured_iteration_precise(&repeat, position),
        "text={text:?} position={position} budget={budget}"
    );
    assert_eq!(actual.steps_left, precise.steps_left, "exact mismatch charge");
    assert_eq!(actual.slots, precise.slots, "including every partial Save");
    assert_eq!(actual.registers, precise.registers, "including the paid Mark");
    assert!(actual.stack.is_empty());
}

#[test]
fn affordable_and_short_bodies_agree_at_every_mismatch_and_refusal_boundary() {
    for groups in [1, 2, 8] {
        for width in [1, 2, 7, 32] {
            let word: String = (0..width)
                .map(|i| char::from(b'a' + (i % 3) as u8))
                .collect();
            for backward in [false, true] {
                let core = format!("{}{}{}*", "(".repeat(groups), word, ")".repeat(groups));
                let pattern = if backward { format!("(?<={core})!") } else { core };
                let regexp = BacktrackRegExp::new(&pattern, "").unwrap();
                let complete_cost = 2 + 4 * groups + width;
                for length in [0, 1, width - 1, width] {
                    for mismatch in 0..=width {
                        let mut text: Vec<_> = word.chars().take(length).collect();
                        if mismatch < text.len() {
                            text[mismatch] = '!';
                        }
                        let text: String = text.into_iter().collect();
                        let start = if backward { length } else { 0 };
                        for budget in 0..=complete_cost as u64 + 3 {
                            compare_body(&regexp, &text, start, budget);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn shared_atom_matching_keeps_class_case_unicode_and_reverse_behavior() {
    for (pattern, flags) in [
        ("(([a-c]))*", "i"),
        (r"((\w))*", "iu"),
        ("((.))*", "s"),
        ("((.))*", ""),
        ("((kſ))*", "iu"),
        ("((kſ))*", "i"),
        ("((😀é))*", "u"),
        ("(?<=((kſ))*)!", "iu"),
        ("(?<=((😀é))*)!", "u"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        let repeat = capture_body(&regexp);
        let complete_cost = 2 + 2 * (repeat.to - repeat.from) + repeat.width;
        for text in ["", "a", "A!", "Ksks!", "😀é😀é!", "a\nb!", "ſ_9\0"] {
            for position in 0..=text.chars().count() {
                for budget in 0..=complete_cost as u64 + 4 {
                    compare_body(&regexp, text, position, budget);
                }
            }
        }
    }
}

#[test]
fn affordable_mismatches_charge_only_examined_literals_and_keep_original_slots() {
    let regexp = BacktrackRegExp::new("((abca))*", "").unwrap();
    let repeat = capture_body(&regexp);
    let slot_count = repeat.to - repeat.from;
    let prefix = 3 + slot_count + slot_count / 2;
    for mismatch in 0..repeat.width {
        let mut text: Vec<_> = "abca".chars().collect();
        text[mismatch] = '!';
        let input = PreparedInput::new(&text.iter().collect::<String>());
        let mut run = Run::new(&regexp, &input, 1000);
        run.slots.fill(Some(123));
        run.registers.fill(97);
        let slots = run.slots.clone();
        let registers = run.registers.clone();
        assert_eq!(run.advance_captured_iteration(&repeat, 0), Ok(None));
        assert_eq!(run.steps_left, 1000 - (prefix + mismatch) as u64);
        assert_eq!(run.slots, slots);
        assert_eq!(run.registers, registers);
    }
    let input = PreparedInput::new("abca");
    let complete_cost = 2 + 2 * slot_count + repeat.width;
    let mut run = Run::new(&regexp, &input, complete_cost as u64);
    assert_eq!(run.advance_captured_iteration(&repeat, 0), Ok(Some(4)));
    assert_eq!(run.steps_left, 0, "no loop-tail instruction is prepaid");
    assert_eq!(&run.slots[repeat.from..repeat.to], &[Some(0), Some(4), Some(0), Some(4)]);
}

#[test]
fn batching_never_skips_counted_tail_writes_or_original_vm_refusal_states() {
    for pattern in ["((ab)){17}", "(?<=((ab)){17})!"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let mut blocks = LiteralBlocks::default();
        let (pc, counted) = (0..regexp.program.len())
            .find_map(|pc| CapturedCounted::at(&regexp, pc, &mut blocks).map(|r| (pc, r)))
            .unwrap();
        let input = PreparedInput::new("ab");
        let start = if counted.body.backward { 2 } else { 0 };
        let complete_cost = 2 + 2 * (counted.body.to - counted.body.from) + counted.body.width;
        for initial_count in [0, 16, 17] {
            for budget in 0..=complete_cost as u64 + 8 {
                let mut actual = Run::new(&regexp, &input, budget);
                let mut reference = Run::new(&regexp, &input, budget);
                reference.repetitions_disabled = true;
                reference.literal_blocks.disabled = true;
                for run in [&mut actual, &mut reference] {
                    run.slots.fill(Some(123));
                    run.registers.fill(97);
                    run.registers[counted.counter] = initial_count;
                }
                assert_eq!(
                    actual.execute(pc, start, &mut Vec::new()),
                    reference.execute(pc, start, &mut Vec::new())
                );
                assert_eq!(actual.steps_left, reference.steps_left);
                assert_eq!(actual.slots, reference.slots);
                assert_eq!(actual.registers, reference.registers,
                    "pattern={pattern} initial={initial_count} budget={budget}");
            }
        }
    }
}
