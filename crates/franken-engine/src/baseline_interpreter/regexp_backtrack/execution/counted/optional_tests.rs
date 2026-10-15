//! Compare the actual optimized executor with its scalar dispatch, not a
//! duplicate scanner. Keep registers and captures visible at every cutoff.
use super::*;
use super::super::PreparedInput;

fn direct_loop(minimum: usize, maximum: Option<usize>, backward: bool) -> BacktrackRegExp {
    let mut regexp = BacktrackRegExp::new("a{0,32}", "").unwrap();
    regexp.registers = 2;
    regexp.program = vec![
        Inst::CountedLoop {
            counter: 0, min: minimum, max: maximum, greedy: true, body: 1, exit: 5,
        },
        Inst::Mark(1),
        Inst::Char { c: 'a', backward },
        Inst::CounterStep { counter: 0, mark: 1, min: minimum },
        Inst::Jump(0),
        Inst::Match,
    ];
    regexp
}

fn compare_execution(
    regexp: &BacktrackRegExp,
    input: &PreparedInput,
    start: usize,
    initial_count: usize,
    budget: u64,
) {
    let mut actual = Run::new(regexp, input, budget);
    let mut scalar = Run::new(regexp, input, budget);
    scalar.repetitions_disabled = true;
    actual.registers = vec![initial_count, 97];
    scalar.registers = actual.registers.clone();
    actual.slots.fill(Some(19));
    scalar.slots.fill(Some(19));
    assert_eq!(
        actual.execute(0, start, &mut Vec::new()),
        scalar.execute(0, start, &mut Vec::new()),
        "start={start} initial_count={initial_count} budget={budget}",
    );
    assert_eq!(actual.steps_left, scalar.steps_left);
    assert_eq!(actual.registers, scalar.registers);
    assert_eq!(actual.slots, scalar.slots);
}

fn compare_search(regexp: &BacktrackRegExp, input: &PreparedInput, start: usize, sticky: bool, budget: u64) {
    let mut actual = Run::new(regexp, input, budget);
    let mut scalar = Run::new(regexp, input, budget);
    scalar.repetitions_disabled = true;
    actual.slots.fill(Some(17));
    scalar.slots.fill(Some(17));
    assert_eq!(actual.search(start, sticky), scalar.search(start, sticky),
        "start={start} sticky={sticky} budget={budget}");
    assert_eq!(actual.steps_left, scalar.steps_left);
    assert_eq!(actual.slots, scalar.slots);
    assert_eq!(actual.registers, scalar.registers);
    assert!(actual.stack.is_empty());
    assert!(actual.capture_seen.iter().all(|seen| !seen));
}

#[test]
fn greedy_optional_scans_preserve_every_write_and_refusal_boundary() {
    for text in ["", "a", "aaaa", "aaabaa", "baaaaa"] {
        let input = PreparedInput::new(text);
        for backward in [false, true] {
            for (minimum, maximum) in [(0, Some(0)), (0, Some(4)), (1, Some(4)), (2, None), (4, Some(4))] {
                let regexp = direct_loop(minimum, maximum, backward);
                for initial_count in [0, 1, 3, 19] {
                    for start in 0..=input.char_len() {
                        for budget in 0..=80 {
                            compare_execution(&regexp, &input, start, initial_count, budget);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn greedy_ranges_retain_all_exits_and_their_exact_register_state() {
    let input = PreparedInput::new("aaaaaa");
    for backward in [false, true] {
        for length in 1..=6 {
            let regexp = direct_loop(2, Some(2 + length), backward);
            let repeat = CountedRepeat::at(&regexp, 0).unwrap();
            let mut run = Run::new(&regexp, &input, 1000);
            run.registers = vec![2, 97];
            let start = if backward { length } else { 0 };
            let mut stack = vec![Frame::Alternative { pc: 5, position: 99 }];
            let end = run.execute_counted_greedy(&repeat, 0, start, Some(2 + length), &mut stack).unwrap();
            assert_eq!(end, if backward { 0 } else { length });
            assert_eq!(stack.len(), 4, "caller prefix plus three range frames");
            assert_eq!(run.steps_left, 1000 - 5 * length as u64);
            for distance in (0..length).rev() {
                let position = if backward { start - distance } else { start + distance };
                let frame = stack.pop().unwrap();
                assert_eq!(run.resume_counted_greedy(frame, &mut stack), (5, position));
                assert_eq!(run.registers[0], 2 + distance);
                assert_eq!(run.registers[1], if distance == 0 { 97 }
                    else if backward { position + 1 } else { position - 1 });
                assert_eq!(stack.len(), if distance == 0 { 1 } else { 4 });
            }
            assert!(matches!(stack[0], Frame::Alternative { position: 99, .. }));
        }
    }
}

#[test]
fn greedy_counted_optional_history_is_constant_size_without_wider_frames() {
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    for length in [17, 128, 8192] {
        let regexp = BacktrackRegExp::new(&format!("(a{{0,{length}}})"), "").unwrap();
        let input = PreparedInput::new(&"a".repeat(length));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut scalar = Run::new(&regexp, &input, 1_000_000);
        scalar.repetitions_disabled = true;
        let mut compact = Vec::new();
        let mut expanded = Vec::new();
        assert_eq!(actual.execute_inner(0, 0, &mut compact, 0), scalar.execute_inner(0, 0, &mut expanded, 0));
        assert_eq!(actual.steps_left, scalar.steps_left);
        assert_eq!(actual.slots, scalar.slots);
        assert_eq!(actual.registers, scalar.registers);
        assert_eq!(compact.len(), 8, "four capture writes, reset and three optional frames");
        assert_eq!(expanded.len(), 5 + 3 * length);
    }
}

#[test]
fn greedy_optional_choices_compose_with_captures_backreferences_and_assertion_floors() {
    for (pattern, flags) in [
        ("(a{0,32})a", ""), ("(a{2,32})aab|a", ""),
        ("(a{17,})a{0,32}b", ""), ("(a{0,32})\\1b", ""),
        ("(?=(a{0,32}))a", ""), ("(?=(a{0,32}))b|a", ""),
        ("(?!(a{0,32}b))a{0,32}c", ""), ("(?!(a{0,32}))b|a", ""),
        ("(?<=(a{0,32})a)b", ""), ("(?<!(a{0,32})b)c", ""),
        ("(?:(a{0,32})b|a){0,3}c", ""), ("(?:a{0,32}){17}", ""),
        ("([a-c]{0,32})(?=!)", "i"), ("(k{0,32})(?=!)", "iu"),
        ("(😀{0,32})(?=!)", "u"), ("(.{0,32})(?=!)", "s"),
        // Capturing and nullable loop bodies must retain scalar execution.
        ("(a){0,32}(?=!)", ""), ("(?:a?){0,32}(?=!)", ""),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in ["", "a", "aaaa", "xaaab", "aaac", "aabac", "Kk!", "😀😀!", "é😀ba\n\na"] {
            let input = PreparedInput::new(text);
            for start in [0, 1, input.char_len(), input.char_len() + 1] {
                for budget in (0..=80).chain([127, 255, 1024]) {
                    for sticky in [false, true] {
                        compare_search(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn greedy_optional_reuse_after_failure_shares_the_original_operation_allowance() {
    let regexp = BacktrackRegExp::new("(a{0,32})(?=!)", "").unwrap();
    let input = PreparedInput::new("aaaa!aa!x!");
    for budget in [0, 1, 2, 8, 31, 63, 1000] {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut scalar = Run::new(&regexp, &input, budget);
        scalar.repetitions_disabled = true;
        for start in [0, 5, 0, input.char_len() + 1] {
            assert_eq!(actual.search(start, false), scalar.search(start, false));
            assert_eq!(actual.steps_left, scalar.steps_left);
            assert_eq!(actual.slots, scalar.slots);
            assert_eq!(actual.registers, scalar.registers);
            assert!(actual.stack.is_empty());
        }
    }
}
