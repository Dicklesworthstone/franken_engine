use super::*;
use super::super::PreparedInput;

fn compare(regexp: &BacktrackRegExp, input: &PreparedInput, start: usize, sticky: bool, budget: u64) {
    let mut actual = Run::new(regexp, input, budget);
    let mut reference = Run::new(regexp, input, budget);
    reference.repetitions_disabled = true;
    actual.slots.fill(Some(17));
    reference.slots.fill(Some(17));
    assert_eq!(actual.search(start, sticky), reference.search(start, sticky),
        "start={start} sticky={sticky} budget={budget}");
    assert_eq!(actual.steps_left, reference.steps_left);
    assert_eq!(actual.slots, reference.slots, "partial capture state");
    assert_eq!(actual.registers, reference.registers, "partial counter and mark state");
    assert!(actual.stack.is_empty());
    assert!(actual.capture_seen.iter().all(|seen| !seen));
}

#[test]
fn counted_lazy_results_and_refusals_match_scalar_execution() {
    for (pattern, flags) in [
        ("(a{0,32}?)b", ""), ("(a{2,32}?)aab", ""),
        ("(a{17,}?)b", ""), ("(a{17,20}?)a", ""),
        ("(a{0,32}?)\\1b", ""), ("a{0,32}?b|a{1,32}?c", ""),
        ("(?=(a{0,32}?b))a{0,32}?b", ""),
        ("(?=(a{0,32}?))b|a", ""), ("(?!(a{0,32}?))b|a", ""),
        ("(?!(a{0,32}?b))a{0,32}?c", ""),
        ("(?<=([a-z]{0,32}?))b", ""), ("(?<=(a{1,32}?)a)b", ""),
        ("(?<!([a-z]{0,32}?)b)c", ""),
        ("(?:(a{0,32}?)b|a)*c", ""),
        ("([a-c]{0,32}?)(?=!)", "i"), ("(k{0,32}?)(?=!)", "iu"),
        ("(😀{0,32}?)(?=!)", "u"), (".{0,32}?a", "s"),
        (".{0,32}?a", ""), ("^a{0,32}?$", "m"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        assert!((0..regexp.program.len()).any(|pc| {
            matches!(regexp.program[pc], Inst::CountedLoop { greedy: false, .. })
                && CountedRepeat::at(&regexp, pc).is_some()
        }), "fixture must exercise a counted lazy atom: {pattern}");
        let texts = ["", "a", "xaaab", "aaac", "aabac", "\na\u{2028}a", "Kk!", "😀😀!", "é😀ba\n\na"];
        for text in texts.into_iter().map(str::to_string).chain([
            "a".repeat(17), format!("{}b", "a".repeat(20)), "a".repeat(33),
        ]) {
            let input = PreparedInput::new(&text);
            let starts: std::collections::BTreeSet<_> = [0, 1, input.char_len() / 2, input.char_len(), input.char_len() + 1]
                .into_iter().collect();
            for start in starts {
                for budget in (0..=128).chain([255, 512, 1024]) {
                    for sticky in [false, true] {
                        compare(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn counted_lazy_partial_writes_and_maximum_keep_the_callers_stack_floor() {
    let input = PreparedInput::new("aaaaa");
    for backward in [false, true] {
        let mut regexp = BacktrackRegExp::new("a{17,}?", "").unwrap();
        regexp.program = vec![
            Inst::CountedLoop { counter: 0, min: 2, max: Some(4), greedy: false, body: 1, exit: 5 },
            Inst::Mark(1), Inst::Char { c: 'a', backward },
            Inst::CounterStep { counter: 0, mark: 1, min: 2 }, Inst::Jump(0),
            if backward { Inst::LineStart } else { Inst::LineEnd }, Inst::Match,
        ];
        for start in 0..=input.char_len() {
            for count in 0..=5 {
                for budget in 0..=64 {
                    let mut actual = Run::new(&regexp, &input, budget);
                    let mut reference = Run::new(&regexp, &input, budget);
                    reference.repetitions_disabled = true;
                    actual.registers[0] = count;
                    reference.registers[0] = count;
                    actual.registers[1] = 97;
                    reference.registers[1] = 97;
                    let mut compact = vec![Frame::Alternative { pc: usize::MAX, position: 71 }];
                    let mut scalar = vec![Frame::Alternative { pc: usize::MAX, position: 71 }];
                    assert_eq!(actual.execute(0, start, &mut compact), reference.execute(0, start, &mut scalar),
                        "backward={backward} start={start} count={count} budget={budget}");
                    assert_eq!(actual.steps_left, reference.steps_left);
                    assert_eq!(actual.registers, reference.registers);
                    assert_eq!(compact.len(), 1);
                    assert!(matches!(compact[0], Frame::Alternative { pc: usize::MAX, position: 71 }));
                }
            }
        }
    }
}

#[test]
fn long_counted_lazy_histories_are_constant_space() {
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    for minimum in [0, 17] {
        for length in [17, 32, 8192] {
            let regexp = BacktrackRegExp::new(&format!("(a{{{minimum},10000}}?)b"), "").unwrap();
            let input = PreparedInput::new(&format!("{}b", "a".repeat(length)));
            let mut actual = Run::new(&regexp, &input, 1_000_000);
            let mut reference = Run::new(&regexp, &input, 1_000_000);
            reference.repetitions_disabled = true;
            let mut compact = Vec::new();
            let mut scalar = Vec::new();
            assert_eq!(actual.execute_inner(0, 0, &mut compact, 0), reference.execute_inner(0, 0, &mut scalar, 0));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert_eq!(compact.len(), if minimum == 0 { 8 } else { 10 });
            assert_eq!(scalar.len(), 6 + 2 * length);
            assert_eq!(compact.iter().filter(|f| matches!(f, Frame::CountedLazy { .. })).count(), 1);
        }
    }
}

#[test]
fn maximum_drops_the_choice_but_keeps_both_original_register_undos() {
    let mut regexp = BacktrackRegExp::new("a{0,32}?", "").unwrap();
    regexp.program = vec![
        Inst::CountedLoop { counter: 0, min: 0, max: Some(2), greedy: false, body: 1, exit: 5 },
        Inst::Mark(1), Inst::Char { c: 'a', backward: false },
        Inst::CounterStep { counter: 0, mark: 1, min: 0 }, Inst::Jump(0),
        Inst::LineEnd, Inst::Match,
    ];
    let input = PreparedInput::new("aa");
    let mut run = Run::new(&regexp, &input, 100);
    run.registers[1] = 97;
    let mut frames = Vec::new();
    assert_eq!(run.execute_inner(0, 0, &mut frames, 0), Ok(Some(2)));
    assert_eq!(run.registers[0], 2);
    assert_eq!(run.registers[1], 1);
    assert_eq!(frames.len(), 2);
    assert!(matches!(frames[0], Frame::Register { register: 1, old: 97 }));
    assert!(matches!(frames[1], Frame::Register { register: 0, old: 0 }));
    // A failing final exit restores those registers, not merely the last step.
    let longer = PreparedInput::new("aaa");
    let mut run = Run::new(&regexp, &longer, 100);
    run.registers[1] = 97;
    assert_eq!(run.execute(0, 0, &mut Vec::new()), Ok(None));
    assert_eq!(run.registers[0], 0);
    assert_eq!(run.registers[1], 97);
}

#[test]
fn optional_counted_laziness_does_not_touch_unneeded_input() {
    let regexp = BacktrackRegExp::new("a{0,32}?", "").unwrap();
    let input = PreparedInput::new(&"a".repeat(8192));
    let mut actual = Run::new(&regexp, &input, 100);
    let mut reference = Run::new(&regexp, &input, 100);
    reference.repetitions_disabled = true;
    actual.registers.fill(97);
    reference.registers.fill(97);
    let mut frames = Vec::new();
    assert_eq!(actual.execute_inner(0, 0, &mut frames, 0), reference.execute_inner(0, 0, &mut Vec::new(), 0));
    assert_eq!(actual.steps_left, reference.steps_left);
    assert_eq!(actual.registers, reference.registers);
    assert!(frames.iter().any(|frame| matches!(frame, Frame::CountedLazy { position: 0, .. })));
}

#[test]
fn counted_and_unbounded_lazy_continuations_share_global_work_and_reuse() {
    let regexp = BacktrackRegExp::new("(a{0,32}?)(b*?)(?=!)", "").unwrap();
    let input = PreparedInput::new("aaa!aabb!x!");
    for budget in [0, 1, 7, 31, 127, 1024] {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.repetitions_disabled = true;
        for start in [0, 4, 8, 0, input.char_len() + 1] {
            assert_eq!(actual.search(start, false), reference.search(start, false));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert!(actual.stack.is_empty());
        }
    }
}
