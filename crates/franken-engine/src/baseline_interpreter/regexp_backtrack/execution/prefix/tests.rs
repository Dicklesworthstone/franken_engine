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
fn choices_nullable_prefixes_and_assertions_are_not_rewritten_as_mandatory() {
    for pattern in ["a|b", "a?b", "a*b", "a{0}", "(?=a)a", "(?!x)a", "(?<=x)a", "(?:)"] {
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
