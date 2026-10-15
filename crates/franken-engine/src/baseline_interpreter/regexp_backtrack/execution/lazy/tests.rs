use super::*;
use super::super::PreparedInput;

fn compare(regexp: &BacktrackRegExp, input: &PreparedInput, start: usize, sticky: bool, budget: u64) {
    let mut actual = Run::new(regexp, input, budget);
    let mut reference = Run::new(regexp, input, budget);
    reference.repetitions_disabled = true;
    actual.slots.fill(Some(17));
    reference.slots.fill(Some(17));
    actual.registers.fill(23);
    reference.registers.fill(23);
    assert_eq!(actual.search(start, sticky), reference.search(start, sticky),
        "start={start} sticky={sticky} budget={budget}");
    assert_eq!(actual.steps_left, reference.steps_left, "exact instruction allowance");
    assert_eq!(actual.slots, reference.slots, "including partial refusal captures");
    assert_eq!(actual.registers, reference.registers, "including partial refusal marks");
    assert!(actual.stack.is_empty());
    assert!(actual.capture_seen.iter().all(|seen| !seen));
}

#[test]
fn selects_only_the_exact_consuming_lazy_loop() {
    for pattern in ["a*?", "a+?", "[a-z]*?", ".*?", "(a*?)", "(?<=a*?)b"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!((0..regexp.program.len()).any(|pc| LazyRepeat::at(&regexp, pc).is_some()), "{pattern}");
    }
    for pattern in ["a*", "(a)*?", "(?:ab)*?", "(?:a?)*?", "a??", "a{0,2}?", "a{17,}?", "a|b"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!((0..regexp.program.len()).all(|pc| LazyRepeat::at(&regexp, pc).is_none()), "{pattern}");
    }
    for defect in 0..6 {
        let mut regexp = BacktrackRegExp::new("a*?", "").unwrap();
        let pc = (0..regexp.program.len()).find(|&pc| LazyRepeat::at(&regexp, pc).is_some()).unwrap();
        match defect {
            0 => regexp.program[pc] = Inst::Split { first: pc + 4, second: pc + 1 },
            1 => regexp.program[pc + 1] = Inst::Mark(regexp.registers),
            2 => regexp.program[pc + 2] = Inst::Save(0),
            3 => regexp.program[pc + 2] = Inst::Class { class: regexp.classes.len(), backward: false },
            4 => regexp.program[pc + 3] = Inst::CheckProgress(regexp.registers),
            5 => regexp.program[pc + 4] = Inst::Jump(pc + 1),
            _ => unreachable!(),
        }
        assert!(LazyRepeat::at(&regexp, pc).is_none(), "defect={defect}");
    }
}

#[test]
fn lazy_exits_preserve_captures_assertion_atomicity_and_all_small_budgets() {
    for (pattern, flags) in [
        ("(a*?)a", ""), ("a*?aab", ""), ("^a*?b$", ""),
        ("(a*?)(a+?)", ""), ("a*?b|a*?c", ""),
        ("(?=(a*?))a*?a", ""), ("(?!(a*?b))a*?c", ""),
        ("(?=(a*?b))c|a", ""), ("(?!(a*?))b|a", ""),
        ("(?:(a*?)b|a)c", ""), ("(?:(a*?)a?)*b", ""),
        ("(?<=([a-z]*?))b", ""), ("(?<=(a*?)a)b", ""),
        ("(?<!([a-z]*?)b)c", ""), ("(a*?)\\1b", ""),
        ("([a-c]*?)(?=!)", "i"), ("(k*?)(?=!)", "iu"),
        ("(k*?)(?=!)", "i"), ("(😀*?)(?=!)", "u"),
        (".*?a", "s"), (".*?a", ""), ("^a*?$", "m"),
        ("((?:😀)*?)(?!(?:.|(.)))", "u"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in ["", "a", "aaaa", "xaaab", "aaac", "aabac", "\na\u{2028}a", "Kk!", "😀😀!", "é😀ba\n\na"] {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for budget in (0..=96).chain([127, 255, 1024]) {
                    for sticky in [false, true] {
                        compare(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn lazy_resume_preserves_every_directional_partial_refusal_write() {
    let input = PreparedInput::new("aaaaa");
    for backward in [false, true] {
        let mut regexp = BacktrackRegExp::new("a*?", "").unwrap();
        regexp.program = vec![
            Inst::Split { first: 5, second: 1 }, Inst::Mark(0),
            Inst::Char { c: 'a', backward }, Inst::CheckProgress(0), Inst::Jump(0),
            if backward { Inst::LineStart } else { Inst::LineEnd }, Inst::Match,
        ];
        for start in 0..=input.char_len() {
            for budget in 0..=48 {
                let mut actual = Run::new(&regexp, &input, budget);
                let mut reference = Run::new(&regexp, &input, budget);
                reference.repetitions_disabled = true;
                actual.registers[0] = 97;
                reference.registers[0] = 97;
                // A surrounding choice must never be consumed by this call.
                let mut compact = vec![Frame::Alternative { pc: usize::MAX, position: 71 }];
                let mut scalar = vec![Frame::Alternative { pc: usize::MAX, position: 71 }];
                assert_eq!(actual.execute(0, start, &mut compact), reference.execute(0, start, &mut scalar),
                    "backward={backward} start={start} budget={budget}");
                assert_eq!(actual.steps_left, reference.steps_left);
                assert_eq!(actual.registers, reference.registers);
                assert_eq!(compact.len(), 1);
                assert!(matches!(compact[0], Frame::Alternative { pc: usize::MAX, position: 71 }));
            }
        }
    }
}

#[test]
fn long_lazy_matches_keep_one_loop_frame_without_widening_ordinary_frames() {
    assert_eq!(std::mem::size_of::<Frame>(), 4 * std::mem::size_of::<usize>());
    for length in [0, 1, 32, 8192] {
        let regexp = BacktrackRegExp::new("(a*?)b", "").unwrap();
        let input = PreparedInput::new(&format!("{}b", "a".repeat(length)));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.repetitions_disabled = true;
        let mut compact = Vec::new();
        let mut scalar = Vec::new();
        assert_eq!(actual.execute_inner(0, 0, &mut compact, 0), reference.execute_inner(0, 0, &mut scalar, 0));
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(compact.len(), 5, "four capture writes and one lazy continuation");
        assert_eq!(scalar.len(), 5 + length);
        assert_eq!(compact.iter().filter(|frame| matches!(frame, Frame::LazyRepeat { .. })).count(), 1);
    }
}

#[test]
fn a_zero_iteration_match_does_not_touch_the_mark_or_eagerly_scan() {
    let regexp = BacktrackRegExp::new("(a*?)(?=a)", "").unwrap();
    let input = PreparedInput::new(&"a".repeat(8192));
    let pc = (0..regexp.program.len()).find(|&pc| LazyRepeat::at(&regexp, pc).is_some()).unwrap();
    let repeat = LazyRepeat::at(&regexp, pc).unwrap();
    let mut actual = Run::new(&regexp, &input, 100);
    let mut reference = Run::new(&regexp, &input, 100);
    reference.repetitions_disabled = true;
    actual.registers[repeat.register] = 97;
    reference.registers[repeat.register] = 97;
    let mut frames = Vec::new();
    assert_eq!(actual.execute_inner(0, 0, &mut frames, 0), reference.execute_inner(0, 0, &mut Vec::new(), 0));
    assert_eq!(actual.registers[repeat.register], 97);
    assert_eq!(actual.steps_left, reference.steps_left);
    assert!(frames.iter().any(|frame| matches!(frame, Frame::LazyRepeat { position: 0, old: 97, .. })));
}

#[test]
fn exhausted_lazy_atoms_restore_the_original_mark_before_outer_alternatives() {
    let mut regexp = BacktrackRegExp::new("a*?", "").unwrap();
    regexp.program = vec![
        Inst::Split { first: 1, second: 8 },
        Inst::Split { first: 6, second: 2 }, Inst::Mark(0),
        Inst::Char { c: 'a', backward: false }, Inst::CheckProgress(0), Inst::Jump(1),
        Inst::Char { c: 'z', backward: false }, Inst::Match,
        Inst::CheckProgress(0), Inst::Match,
    ];
    let input = PreparedInput::new("aaaa");
    for old in [0, 1, 97] {
        for budget in 0..=64 {
            let mut actual = Run::new(&regexp, &input, budget);
            let mut reference = Run::new(&regexp, &input, budget);
            reference.repetitions_disabled = true;
            actual.registers[0] = old;
            reference.registers[0] = old;
            assert_eq!(actual.execute(0, 0, &mut Vec::new()), reference.execute(0, 0, &mut Vec::new()));
            assert_eq!(actual.registers, reference.registers);
            assert_eq!(actual.steps_left, reference.steps_left);
        }
    }
}

#[test]
fn reused_lazy_searches_share_one_allowance_including_after_refusal() {
    let regexp = BacktrackRegExp::new("(a*?)(?=!)", "").unwrap();
    let input = PreparedInput::new("aaa!xxaa!x!");
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
