use super::*;
use super::super::{PreparedInput, Run};

fn compare(regexp: &BacktrackRegExp, input: &PreparedInput, start: usize, sticky: bool, budget: u64) {
    let mut actual = Run::new(regexp, input, budget);
    let mut reference = Run::new(regexp, input, budget);
    reference.repetitions_disabled = true;
    actual.slots.fill(Some(17));
    reference.slots.fill(Some(17));
    assert_eq!(actual.search(start, sticky), reference.search(start, sticky),
        "start={start} sticky={sticky} budget={budget}");
    assert_eq!(actual.steps_left, reference.steps_left);
    assert_eq!(actual.slots, reference.slots, "including partial refusal captures");
    assert_eq!(actual.registers, reference.registers, "including partial refusal registers");
    assert!(actual.stack.is_empty());
    assert!(actual.capture_seen.iter().all(|seen| !seen));
}

#[test]
fn recognizes_only_the_compilers_supported_counted_shapes() {
    for pattern in ["a{17}", "a{17}?", "a{17,18}", "a{17,}", "a{17,18}?", "(?:a){17}", "[a-c]{17}", ".{17}", "(a{17})", "(?<=a{17})b", "(?:ab){17}"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!((0..regexp.program.len()).any(|pc| CountedRepeat::at(&regexp, pc).is_some()), "{pattern}");
    }
    for pattern in ["(a){17}", "(?:a?){17}", "a*", "a{16}"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!((0..regexp.program.len()).all(|pc| CountedRepeat::at(&regexp, pc).is_none()), "{pattern}");
    }
}

fn direct_loop(count: usize, backward: bool) -> BacktrackRegExp {
    let mut regexp = BacktrackRegExp::new("a{17}", "").unwrap();
    regexp.registers = 2;
    regexp.program = vec![
        Inst::CountedLoop { counter: 0, min: count, max: Some(count), greedy: true, body: 1, exit: 5 },
        Inst::Mark(1),
        Inst::Char { c: 'a', backward },
        Inst::CounterStep { counter: 0, mark: 1, min: count },
        Inst::Jump(0),
        Inst::Match,
    ];
    regexp
}

#[test]
fn every_write_and_refusal_boundary_matches_scalar_execution() {
    for text in ["", "a", "aaaa", "aaabaa", "baaaaa"] {
        let input = PreparedInput::new(text);
        for backward in [false, true] {
            for count in [0, 1, 2, 4, 17] {
                let regexp = direct_loop(count, backward);
                assert!(CountedRepeat::at(&regexp, 0).is_some());
                for initial_count in [0, 1, 3, 19] {
                    for start in 0..=input.char_len() {
                        for budget in 0..=100 {
                            let mut actual = Run::new(&regexp, &input, budget);
                            let mut reference = Run::new(&regexp, &input, budget);
                            reference.repetitions_disabled = true;
                            actual.registers = vec![initial_count, 97];
                            reference.registers = actual.registers.clone();
                            assert_eq!(actual.execute(0, start, &mut Vec::new()), reference.execute(0, start, &mut Vec::new()),
                                "text={text:?} backward={backward} count={count} initial={initial_count} start={start} budget={budget}");
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
fn failed_body_unwinds_and_assertions_preserve_exact_captures() {
    let texts = [
        String::new(), "a".repeat(16), "a".repeat(17), "a".repeat(18),
        format!("x{}b", "a".repeat(34)), format!("{}!", "abc".repeat(6)),
        format!("{}!", "Kk".repeat(9)), format!("{}!", "😀".repeat(18)),
        format!("{}\n!", "a".repeat(17)),
    ];
    for (pattern, flags) in [
        ("(a{17})a", ""), ("(a{17,18})a", ""), ("(a{17,18}?)a", ""),
        ("(a{17,})b|a", ""), ("(a{17,}?)a", ""), ("(a{17})\\1", ""),
        ("(?=(a{17}))a+", ""), ("(?!(a{17})b)a+", ""),
        ("(?<=(a{17}))b", ""), ("(?<!(a{17}))b", ""),
        ("(?:(a{17})b|a)+", ""), ("(?:a{17}){2}", ""),
        ("([a-c]{17})(?=!)", "i"), ("(k{17})(?=!)", "iu"),
        ("(😀{17})(?=!)", "u"), ("(.{17})(?=!)", "s"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in &texts {
            let input = PreparedInput::new(text);
            for start in [0, 1, input.char_len(), input.char_len() + 1] {
                for budget in (0..=128).chain([255, 511, 4096]) {
                    for sticky in [false, true] {
                        compare(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn fixed_count_uses_two_undo_frames_without_widening_frames() {
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    for length in [17, 128, 8192] {
        let regexp = BacktrackRegExp::new(&format!("(a{{{length}}})"), "").unwrap();
        let input = PreparedInput::new(&"a".repeat(length));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.repetitions_disabled = true;
        let mut compact = Vec::new();
        let mut scalar = Vec::new();
        assert_eq!(actual.execute_inner(0, 0, &mut compact, 0), reference.execute_inner(0, 0, &mut scalar, 0));
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(compact.len(), 7, "four capture writes, reset, and two loop writes");
        assert_eq!(scalar.len(), 5 + 2 * length);
    }
}

#[test]
fn shared_search_allowance_and_reuse_after_refusal_remain_unchanged() {
    let regexp = BacktrackRegExp::new("(a{17})(?=!)", "").unwrap();
    let input = PreparedInput::new(&format!("{}!{}!", "a".repeat(17), "a".repeat(17)));
    for budget in [0, 1, 86, 100, 200, 1000] {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.repetitions_disabled = true;
        for start in [0, 18, 0, input.char_len() + 1] {
            assert_eq!(actual.search(start, false), reference.search(start, false));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert!(actual.stack.is_empty());
        }
    }
}

#[test]
fn malformed_shapes_are_never_fused() {
    let mut regexp = direct_loop(17, false);
    regexp.program[3] = Inst::CounterStep { counter: 1, mark: 1, min: 17 };
    assert!(CountedRepeat::at(&regexp, 0).is_none());
    regexp = direct_loop(17, false);
    regexp.program[4] = Inst::Jump(1);
    assert!(CountedRepeat::at(&regexp, 0).is_none());
    regexp = direct_loop(17, false);
    regexp.program[2] = Inst::Char { c: 'a', backward: true };
    regexp.registers = 1;
    assert!(CountedRepeat::at(&regexp, 0).is_none());
    assert!(CountedRepeat::at(&regexp, usize::MAX).is_none());
}
