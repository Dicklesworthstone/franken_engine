use super::*;
use super::super::{BacktrackError, Captures, PreparedInput};

/// Scalar candidate search, deliberately bypassing BOTH start accelerators.
/// The shared VM remains authoritative for captures, backtracking and refusal.
fn scalar_search(
    run: &mut Run<'_>,
    start: usize,
    sticky: bool,
) -> Result<Option<Captures>, BacktrackError> {
    run.registers.fill(0);
    let length = run.input.chars.len();
    if start <= length {
        run.slots.fill(None);
    }
    let mut stack = Vec::new();
    for at in start..=length {
        run.candidate_executions += 1;
        if run.execute(0, at, &mut stack)?.is_some() {
            return Ok(Some(run.slots.chunks(2).map(|pair| match (pair[0], pair[1]) {
                (Some(from), Some(to)) => {
                    Some((run.input.byte_offset(from), run.input.byte_offset(to)))
                }
                _ => None,
            }).collect()));
        }
        if sticky {
            break;
        }
    }
    Ok(None)
}

fn assert_search(
    regexp: &BacktrackRegExp,
    input: &PreparedInput,
    start: usize,
    sticky: bool,
    budget: u64,
) {
    let mut actual = Run::new(regexp, input, budget);
    let mut reference = Run::new(regexp, input, budget);
    // Out-of-range starts must leave prior captures alone too.
    actual.slots.fill(Some(17));
    reference.slots.fill(Some(17));
    actual.registers.fill(23);
    reference.registers.fill(23);
    let result = actual.search(start, sticky);
    let expected = scalar_search(&mut reference, start, sticky);
    assert_eq!(result, expected, "start={start} sticky={sticky} budget={budget}");
    assert_eq!(actual.steps_left, reference.steps_left, "remaining budget");
    assert_eq!(actual.slots, reference.slots, "including partial refusal captures");
    assert_eq!(actual.registers, reference.registers, "including partial refusal registers");
    assert!(actual.stack.is_empty());
}

#[test]
fn grouped_classes_anchors_and_unicode_match_at_every_small_budget() {
    let patterns = [
        ("((ab))(?=c)", ""),
        ("((a))\\1", "i"),
        ("([a-c])\\1", "i"),
        ("([^a-c])(?=.)", ""),
        ("(.)x", "s"),
        ("(.)x", ""),
        ("^((a))", "m"),
        ("(a)$", "m"),
        ("\\b(a)", ""),
        ("\\B(a)", ""),
        ("(k)(?=.)", "iu"),
        ("(😀)(.)", "u"),
        ("ab(?=c)", ""),
        ("a|bc", ""),
        ("a?b", ""),
        ("(?=a)a", ""),
        ("(?<!x)a", ""),
        ("(a?)*", ""),
    ];
    let texts = ["", "a", "xxabc", "aAx", "cc", "\nax", "a\rx", "\u{2028}a", "Kx", "x😀z"];
    for (pattern, flags) in patterns {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in texts {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for budget in 0..=96 {
                    for sticky in [false, true] {
                        assert_search(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn clear_and_register_costs_keep_every_refusal_state_exact() {
    let mut regexp = BacktrackRegExp::new("(z)", "").unwrap();
    regexp.registers = 2;
    regexp.program = vec![
        Inst::Save(0), Inst::Save(2), Inst::Mark(0), Inst::CounterReset(1),
        Inst::Clear { from: 0, to: 4 },
        Inst::Char { c: 'z', backward: false },
        Inst::Save(1), Inst::Match,
    ];
    let prefix = StartPrefix::new(&regexp).expect("straight prefix");
    assert_eq!(prefix.checks[0].cost, 10);
    let input = PreparedInput::new("xxxz");
    for budget in 0..=80 {
        for start in 0..=input.char_len() + 1 {
            assert_search(&regexp, &input, start, false, budget);
        }
    }
}

#[test]
fn choices_are_analyzed_but_nullable_success_and_assertions_still_execute() {
    for pattern in ["a|b", "a?b", "a*b", "a??b"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let prefix = StartPrefix::new(&regexp).expect(pattern);
        assert!(prefix.branch.is_some(), "{pattern}");
        // Neither choice is promoted to a mandatory character. A later
        // branch can match, and its captures/budget must come from the VM.
        assert_search(&regexp, &PreparedInput::new("xb"), 0, false, 10_000);
    }
    for pattern in ["a{0}", "(?=a)a", "(?!x)a", "(?<=x)a", "(?:)"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        assert!(StartPrefix::new(&regexp).is_none(), "{pattern}");
    }
    // Oversized initial bookkeeping is a bounded analysis miss, not refusal.
    let pattern = format!("{}z{}", "(".repeat(70), ")".repeat(70));
    let regexp = BacktrackRegExp::new(&pattern, "").unwrap();
    assert!(StartPrefix::new(&regexp).is_none());
    assert_search(&regexp, &PreparedInput::new("xz"), 0, false, 10_000);
}

#[test]
fn long_common_prefix_misses_do_not_enter_the_vm_or_change_its_allowance() {
    for pattern in ["((aaaaab))(?=x)", "aaaaab(?=x)"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let input = PreparedInput::new(&format!("{}aaaaabx", "a".repeat(8192)));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        assert_eq!(actual.search(0, false), scalar_search(&mut reference, 0, false));
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.candidate_executions, 1);
        assert_eq!(reference.candidate_executions, 8193);
    }
}

#[test]
fn skip_batches_are_bounded_allocation_free_and_leave_captures_untouched() {
    let regexp = BacktrackRegExp::new("((z))(?=z)", "").unwrap();
    let input = PreparedInput::new(&"x".repeat(1024));
    let prefix = StartPrefix::new(&regexp).unwrap();
    let cost = prefix.checks[0].cost;
    let mut run = Run::new(&regexp, &input, u64::MAX);
    run.slots.fill(Some(17));
    let original = run.slots.clone();
    assert_eq!(run.skip_prefix_misses(0, &prefix), MAX_SKIP_BATCH);
    assert_eq!(run.steps_left, u64::MAX - cost * MAX_SKIP_BATCH as u64);
    assert_eq!(run.slots, original);
    assert_eq!(run.stack.capacity(), 0);
    run.steps_left = cost - 1;
    assert_eq!(run.skip_prefix_misses(256, &prefix), 0);
    assert_eq!(run.steps_left, cost - 1);
    assert_eq!(run.skip_prefix_misses(input.char_len(), &prefix), 0);
}

#[test]
fn reused_searches_share_one_budget_and_clear_previous_capture_state() {
    let regexp = BacktrackRegExp::new("((ab))(?=x)", "").unwrap();
    let input = PreparedInput::new("zzabxxabxzzz");
    for budget in 0..=192 {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        for start in [0, 3, 6, 8, 0, 99] {
            assert_eq!(actual.search(start, false), scalar_search(&mut reference, start, false));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
        }
    }
}

#[test]
fn branching_search_matches_the_vm_at_every_budget_start_and_sticky_mode() {
    for (pattern, flags) in [
        ("(?:(ab)|(ac))(?=!)", ""),
        ("((a)?b)|((c)?d)", ""),
        ("((a)??b)|(c)", ""),
        ("((a)*)b|c", ""),
        ("((a)*?)b|c", ""),
        ("(?:(a)|b){0,2}c", ""),
        ("(?:(a)|b){17,20}c", ""),
        ("(?:[a-c]|[^x-z])(?=!)", "i"),
        ("(?:(k)|(ſ)|(Σ)|(😀))(?=!)", "iu"),
        ("(?:(k)|(ſ)|(Σ)|(😀))(?=!)", "i"),
        ("(?:^a|b$|\\bc|\\Bd)", "m"),
        ("(?:.|a)b", "s"),
        ("(?:.|a)b", ""),
        ("(?:(a)\\1|b)", ""),
        ("(?:(?=a)a|b)", ""),
        ("(?:(?!a)b|a)", ""),
        ("(?:(?<=x)a|b)", ""),
        ("(?:(a)|)", ""),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in ["", "x", "ab!ac!", "aac", "xb", "\nc\u{2028}d", "K!ſ!ς!😀!"] {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for budget in (0..=96).chain([127, 255, 1024]) {
                    for sticky in [false, true] {
                        assert_search(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn alternating_and_optional_prefix_misses_bypass_candidate_execution() {
    for (pattern, tail) in [
        ("(?:(cat)|(dog))(?=!)", "dog!"),
        ("((ab)?c)(?=!)", "c!"),
        ("((ab)??c)(?=!)", "c!"),
        ("(?:[a-c]|[m-p])(?=!)", "n!"),
        ("a(?:b|c)(?=!)", "ac!"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let prefix = StartPrefix::new(&regexp).unwrap();
        assert!(prefix.branch.is_some(), "{pattern}");
        let input = PreparedInput::new(&format!("{}{tail}", "x".repeat(4096)));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        assert_eq!(actual.search(0, false), scalar_search(&mut reference, 0, false));
        assert_eq!(actual.steps_left, reference.steps_left, "{pattern}");
        assert_eq!(actual.slots, reference.slots, "{pattern}");
        assert_eq!(actual.registers, reference.registers, "{pattern}");
        assert_eq!(actual.candidate_executions, 1, "{pattern}");
        assert_eq!(reference.candidate_executions, 4097, "{pattern}");
    }
}

#[test]
fn branch_rejection_charges_all_failed_paths_without_mutating_state() {
    let mut regexp = BacktrackRegExp::new("(a)|b", "").unwrap();
    regexp.registers = 2;
    regexp.program = vec![
        Inst::Save(0),
        Inst::Split { first: 2, second: 9 },
        Inst::Save(2),
        Inst::Mark(0),
        Inst::CounterReset(1),
        Inst::Clear { from: 0, to: 4 },
        Inst::Char { c: 'a', backward: false },
        Inst::Char { c: 'b', backward: false },
        Inst::Jump(14),
        Inst::Save(3),
        Inst::Mark(1),
        Inst::Char { c: 'c', backward: false },
        Inst::Char { c: 'd', backward: false },
        Inst::Jump(14),
        Inst::Save(1),
        Inst::Match,
    ];
    let prefix = StartPrefix::new(&regexp).unwrap();
    let input = PreparedInput::new(&"x".repeat(1024));
    // First failed arm: Save, Split, Save, Mark, Reset, Clear(+4), Char = 11.
    // Second failed arm: Save, Mark, Char = 3. Undo frames have no step cost.
    assert_eq!(prefix.rejection_cost(&regexp, &input.chars, 0, 14), Some(14));
    assert_eq!(prefix.rejection_cost(&regexp, &input.chars, 0, 13), None);
    let mut run = Run::new(&regexp, &input, u64::MAX);
    run.slots.fill(Some(17));
    run.registers.fill(23);
    assert_eq!(run.skip_prefix_misses(0, &prefix), MAX_SKIP_BATCH);
    assert_eq!(run.steps_left, u64::MAX - 14 * MAX_SKIP_BATCH as u64);
    assert!(run.slots.iter().all(|slot| *slot == Some(17)));
    assert!(run.registers.iter().all(|register| *register == 23));
    assert_eq!(run.stack.capacity(), 0);
    let input = PreparedInput::new("xabxcd");
    for start in 0..=input.char_len() + 1 {
        for budget in 0..=128 {
            assert_search(&regexp, &input, start, false, budget);
        }
    }
}

#[test]
fn nullable_branches_and_state_reading_instructions_never_supply_a_rejection() {
    for (pattern, text) in [
        ("a|", "x"),
        ("(?:a|b)?", "x"),
        ("(a)\\1|b", "aa"),
        ("(?=a)a|b", "a"),
        ("(?!b)a|b", "a"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let input = PreparedInput::new(text);
        let prefix = StartPrefix::new(&regexp).unwrap();
        assert_eq!(prefix.rejection_cost(&regexp, &input.chars, 0, u64::MAX), None);
        assert_search(&regexp, &input, 0, false, 10_000);
    }
}

#[test]
fn branch_analysis_limits_fall_back_without_changing_guest_errors() {
    let mut regexp = BacktrackRegExp::new("a|b", "").unwrap();
    let input = PreparedInput::new("x");
    // A cycle through Split exceeds the inline alternative stack; a Jump
    // cycle exceeds the instruction-analysis limit instead. Neither limit
    // replaces the VM's budget error or its partial capture state.
    for program in [
        vec![Inst::Save(0), Inst::Split { first: 1, second: 2 }, Inst::Match],
        vec![Inst::Save(0), Inst::Split { first: 2, second: 3 }, Inst::Jump(2), Inst::Match],
    ] {
        regexp.program = program;
        let prefix = StartPrefix::new(&regexp).unwrap();
        assert_eq!(prefix.rejection_cost(&regexp, &input.chars, 0, u64::MAX), None);
        for budget in 0..=160 {
            assert_search(&regexp, &input, 0, false, budget);
        }
    }
    // A finite program past the analysis limit must still be able to match.
    regexp.program = vec![Inst::Save(0), Inst::Split { first: 2, second: 2 }];
    regexp.program.extend((0..MAX_PREFIX_INSTRUCTIONS + 1).map(|_| Inst::Save(0)));
    regexp.program.extend([
        Inst::Char { c: 'x', backward: false }, Inst::Save(1), Inst::Match,
    ]);
    let prefix = StartPrefix::new(&regexp).unwrap();
    assert_eq!(prefix.rejection_cost(&regexp, &input.chars, 0, u64::MAX), None);
    assert_search(&regexp, &input, 0, false, 10_000);
}

#[test]
fn branch_search_reuse_keeps_one_allowance_through_success_failure_and_sticky_calls() {
    let regexp = BacktrackRegExp::new("(?:(ab)|(cd))(?=!)", "").unwrap();
    let input = PreparedInput::new("xxab!xxcd!xxx");
    for budget in 0..=256 {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        for (start, sticky) in [(0, false), (5, false), (7, true), (10, false), (0, true), (99, false)] {
            assert_eq!(actual.search(start, sticky), scalar_search(&mut reference, start, sticky));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
        }
    }
}
