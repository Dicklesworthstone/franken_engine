//! Compare the optimized search loop with the original per-candidate reset.
//! Both enter the unchanged opcode executor; the older executor differential
//! in tests.rs independently covers that executor's assertion/undo semantics.

use super::*;

fn legacy_search(
    run: &mut Run<'_>,
    start: usize,
    sticky: bool,
) -> Result<Option<Captures>, BacktrackError> {
    run.registers.fill(0);
    let mut stack = Vec::new();
    let mut at = start;
    while at <= run.input.char_len() {
        run.slots.fill(None);
        if run.execute(0, at, &mut stack)?.is_some() {
            return Ok(Some(
                run.slots
                    .chunks(2)
                    .map(|pair| match (pair[0], pair[1]) {
                        (Some(from), Some(to)) => {
                            Some((run.input.byte_offset(from), run.input.byte_offset(to)))
                        }
                        _ => None,
                    })
                    .collect(),
            ));
        }
        if sticky {
            break;
        }
        at += 1;
    }
    Ok(None)
}

#[test]
fn candidate_retries_preserve_captures_scratch_and_exact_work_boundaries() {
    let patterns = [
        "z()()()(?=)",
        "(a)b|c",
        "(?=(a+))a*b\\1",
        "(.*?)a(?!(a+)b\\2c)\\2(.*)",
        "(?:(a)|(b))+c",
        "(?:(?=(a))a|b)+c",
        "(?<=((a)|(b))+)(c)",
        "(?!(a+))b|(?=(c))c",
        "((a)?)*b",
        "(?:a|b(?!c)){0,30}d",
        "(?:(a)|(b)){17,20}(?=)",
        "(?:a*){17,40}b(?=)",
        "a(?=(b))c|b",
        "(?=(a(?=(b))))ac|b",
        "(?<name>a)\\k<name>|b",
        "(?<=(\\d+)(\\d+))$",
    ];
    for pattern in patterns {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        for text in ["", "x", "abc", "baabac", "aaaabc", "1053", "ababbc", "é😀abc"] {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for sticky in [false, true] {
                    for budget in (0..=96).chain([127, 255, 1024, 10_000]) {
                        let mut candidate = Run::new(&regexp, &input, budget);
                        let mut reference = Run::new(&regexp, &input, budget);
                        assert_eq!(
                            candidate.search(start, sticky),
                            legacy_search(&mut reference, start, sticky),
                            "/{pattern}/ {text:?} start={start} sticky={sticky} budget={budget}"
                        );
                        assert_eq!(candidate.steps_left, reference.steps_left);
                        assert_eq!(candidate.slots, reference.slots);
                        assert_eq!(candidate.registers, reference.registers);
                        assert!(candidate.stack.is_empty());
                        assert!(candidate.capture_seen.iter().all(|seen| !seen));
                    }
                }
            }
        }
    }
}

#[test]
fn global_reuse_and_retry_after_refusal_begin_with_clean_captures() {
    for pattern in ["(a)b|c", "(?=(a+))a*b\\1", "(?:(a)|(b))+c", "a(?=(b))c|b"] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let input = PreparedInput::new("abcbaaabacababcb");
        for initial_budget in [0, 1, 2, 7, 31, 255, 10_000] {
            let mut candidate = Run::new(&regexp, &input, initial_budget);
            let mut reference = Run::new(&regexp, &input, initial_budget);
            for start in [0, 2, 3, 8, 0, input.char_len(), usize::MAX, 1] {
                assert_eq!(
                    candidate.search(start, false),
                    legacy_search(&mut reference, start, false)
                );
                assert_eq!(candidate.steps_left, reference.steps_left);
                assert_eq!(candidate.slots, reference.slots);
                assert_eq!(candidate.registers, reference.registers);
                assert!(candidate.stack.is_empty());
            }
            // Test-only refill exercises reset after partial capture writes.
            // Production Run never refunds the operation's shared allowance.
            candidate.steps_left = 10_000;
            reference.steps_left = 10_000;
            assert_eq!(candidate.search(0, false), legacy_search(&mut reference, 0, false));
            assert_eq!(candidate.slots, reference.slots);
            assert_eq!(candidate.steps_left, reference.steps_left);
        }
    }
}

#[test]
fn failed_attempts_restore_all_captures_before_the_next_candidate() {
    for pattern in [
        "(?=(a+))a*c",
        "(?:(a)|(b))+c",
        "(?=(a(?=(b))))ac",
        "(?!(a))(?=(b+))b*c",
    ] {
        let regexp = BacktrackRegExp::new(pattern, "").unwrap();
        let input = PreparedInput::new("aababbaba");
        let mut run = Run::new(&regexp, &input, 100_000);
        let mut stack = Vec::new();
        for at in 0..=input.char_len() {
            assert_eq!(run.execute(0, at, &mut stack), Ok(None));
            assert!(run.slots.iter().all(Option::is_none), "/{pattern}/ at={at}");
            assert!(stack.is_empty());
        }
    }
}

#[test]
fn many_unentered_groups_do_not_change_search_results_or_instruction_cost() {
    let pattern = format!("needle{}", "()".repeat(8192));
    let regexp = BacktrackRegExp::new(&pattern, "").unwrap();
    let input = PreparedInput::new(&format!("{}needle", "x".repeat(32_768)));
    let budget = 1_000_000;
    let mut run = Run::new(&regexp, &input, budget);
    let captures = run.search(0, false).unwrap().unwrap();
    assert_eq!(captures.len(), 8193);
    assert_eq!(captures[0], Some((32_768, 32_774)));
    assert!(captures[1..].iter().all(|span| *span == Some((32_774, 32_774))));
    // Each failed start executes Save(0), Char('n'). The matching attempt
    // executes Save(0), six literals, two saves per empty group, Save(1), Match.
    let expected = 2 * 32_768 + 1 + 6 + 2 * 8192 + 1 + 1;
    assert_eq!(budget - run.steps_remaining(), expected);
}
