use super::*;
use super::super::PreparedInput;

#[test]
fn every_ascii_bit_matches_the_original_complete_class_predicate() {
    for (pattern, flags) in [
        (r"\d", ""), (r"\D", ""), (r"\w", ""), (r"\W", ""),
        (r"\s", ""), (r"\S", ""), (r"[a-zA-Z0-9_]", ""),
        (r"[^a-cX-Z]", "i"), (r"[a-z]", "iu"), (r"[^k]", "iu"),
        (r"[\x00-\x40\x7f]", ""), (r"[^\x00-\x40\x7f]", ""),
        (r"\p{L}", "u"), (r"\P{L}", "u"), (r"[\p{L}\p{N}_]", "u"),
        (r"[^\p{Lu}\d]", "iu"), (r"[\p{Lu}]", "iu"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        assert_eq!(regexp.classes.len(), 1, "{pattern}");
        let mut cache = ClassMatches::default();
        // Walk both bitmaps and their boundaries in both directions. The
        // second pass must include cached false results, not just matches.
        for pass in 0..3 {
            for value in 0..=127_u8 {
                let c = char::from(if pass == 1 { 127 - value } else { value });
                let expected = regexp.class_matches(&regexp.classes[0], c);
                assert_eq!(cache.matches(&regexp, 0, c), expected,
                    "/{pattern}/{flags}, {c:?}, pass={pass}");
            }
        }
        assert_eq!(cache.evaluations, 128);
        assert_eq!(cache.hits, 256);
    }
}

#[test]
fn collisions_replace_positive_and_negative_membership_together() {
    let regexp = BacktrackRegExp::new("[a][^b][c][^d][e][^f][g][^h][i]", "").unwrap();
    assert!(regexp.classes.len() > 2 * CACHE_SLOTS);
    let mut cache = ClassMatches::default();
    for _ in 0..3 {
        for class in [0, 4, 8, 0, 1, 5, 1, 2, 6, 2, 3, 7, 3] {
            for c in ['\0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', '\x7f'] {
                let expected = regexp.class_matches(&regexp.classes[class], c);
                assert_eq!(cache.matches(&regexp, class, c), expected);
                let before = cache.evaluations;
                assert_eq!(cache.matches(&regexp, class, c), expected);
                assert_eq!(cache.evaluations, before, "an immediate hit cannot recompute");
            }
        }
    }
    assert_eq!(cache.entries.len(), CACHE_SLOTS);
    assert!(std::mem::size_of::<ClassMatches>() <= 256, "bounded per-operation metadata");
}

#[test]
fn unicode_is_uncached_and_does_not_evict_ascii_results() {
    for flags in ["", "i", "u", "iu"] {
        let regexp = BacktrackRegExp::new("[a-zKſΣé😀]", flags).unwrap();
        let mut cache = ClassMatches::default();
        let ascii = cache.matches(&regexp, 0, 'k');
        for c in ['K', 'ſ', 'Σ', 'σ', 'ς', 'é', 'É', '😀', '\u{80}', '\u{10ffff}'] {
            for _ in 0..2 {
                let before = cache.evaluations;
                assert_eq!(cache.matches(&regexp, 0, c), regexp.class_matches(&regexp.classes[0], c));
                assert_eq!(cache.evaluations, before + 1);
            }
        }
        let before = cache.evaluations;
        assert_eq!(cache.matches(&regexp, 0, 'k'), ascii);
        assert_eq!(cache.evaluations, before);
    }
}

fn compare(regexp: &BacktrackRegExp, input: &PreparedInput, start: usize, sticky: bool, budget: u64) {
    let mut actual = Run::new(regexp, input, budget);
    let mut reference = Run::new(regexp, input, budget);
    reference.class_matches.disabled = true;
    actual.slots.fill(Some(17));
    reference.slots.fill(Some(17));
    actual.registers.fill(23);
    reference.registers.fill(23);
    assert_eq!(actual.search(start, sticky), reference.search(start, sticky),
        "start={start}, sticky={sticky}, budget={budget}");
    assert_eq!(actual.steps_left, reference.steps_left, "cache warmth cannot donate work");
    assert_eq!(actual.slots, reference.slots, "partial refusal captures");
    assert_eq!(actual.registers, reference.registers, "partial refusal registers");
    assert!(actual.stack.is_empty());
    assert!(actual.capture_seen.iter().all(|seen| !seen));
}

#[test]
fn cached_and_uncached_execution_agree_at_every_small_refusal_boundary() {
    for (pattern, flags) in [
        (r"(?=)([a-z]+)(?=!)", ""), (r"(?=)([a-z]+?)(?=!)", "i"),
        (r"(?=)([a-z]{0,32})(?=!)", ""), (r"(?=)([a-z]{0,32}?)(?=!)", "i"),
        (r"(?=)([a-z]{17,})(?=!)", ""), (r"(?=)([a-z]{17,}?)(?=!)", ""),
        (r"(?=)([a-z])+(?=!)", ""), (r"(?=)(([a-z])|([0-9]))+!", ""),
        (r"(?<=([a-z]*))!", ""), (r"(?<=([a-z]*?))!", ""),
        (r"(?<=([a-z]{0,32}))!", ""), (r"(?<=([a-z]{0,32}?))!", ""),
        (r"(?=)([a-z]+)\1", "i"), (r"(?!(\d))([\w]+)!", ""),
        (r"(?=)([^a-z]+?)(?=!)", "i"), (r"(?=)([\p{L}\p{N}_]+)(?=!)", "u"),
        (r"(?=)([^\p{Lu}]{0,32}?)(?=!)", "iu"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in ["", "!", "abAB!", "aa11!", "xxabca!", "abab", "a\nZ!", "KkſsÉé😀!"] {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for budget in (0..=48).chain([63, 127, 4096]) {
                    for sticky in [false, true] {
                        compare(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn every_execution_path_reuses_predicates_without_reducing_charged_work() {
    for pattern in [
        r"(?=)([a-z]+)(?=!)", r"(?=)([a-z]+?)(?=!)",
        r"(?=)([a-z]{0,10000})(?=!)", r"(?=)([a-z]{0,10000}?)(?=!)",
        r"(?=)([a-z]{8192})(?=!)", r"(?=)([a-z])+(?=!)",
        r"(?=)([\p{L}\p{N}_]+)(?=!)",
    ] {
        let regexp = BacktrackRegExp::new(pattern, "u").unwrap();
        let input = PreparedInput::new(&format!("{}!", "a".repeat(8192)));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.class_matches.disabled = true;
        assert_eq!(actual.search(0, true), reference.search(0, true), "{pattern}");
        assert_eq!(actual.steps_left, reference.steps_left, "{pattern}");
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert!(actual.class_matches.evaluations <= 2, "{pattern}");
        assert!(actual.class_matches.hits >= 8191, "{pattern}");
        assert!(reference.class_matches.evaluations >= 8192, "{pattern}");
    }
}

#[test]
fn eof_and_unaffordable_instructions_never_prepare_membership() {
    let regexp = BacktrackRegExp::new(r"(?=)[a-z]", "").unwrap();
    let empty = PreparedInput::new("");
    let mut run = Run::new(&regexp, &empty, 1000);
    assert_eq!(run.search(0, true).unwrap(), None);
    assert_eq!(run.class_matches.evaluations, 0);
    assert!(run.class_matches.entries.iter().all(Option::is_none));
    let input = PreparedInput::new("abc");
    let mut run = Run::new(&regexp, &input, 0);
    assert!(run.search(0, true).is_err());
    assert_eq!(run.class_matches.evaluations, 0);
    assert!(run.class_matches.entries.iter().all(Option::is_none));
}

#[test]
fn warm_caches_survive_search_reuse_but_not_new_programs() {
    let regexp = BacktrackRegExp::new(r"(?=)([a-z]+?)(?=!)", "i").unwrap();
    let input = PreparedInput::new("aaAA!bbBB!ccCC!");
    for budget in (0..=96).chain([127, 255, 4096]) {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.class_matches.disabled = true;
        for start in [0, 5, 10, 0, usize::MAX, 5] {
            assert_eq!(actual.search(start, false), reference.search(start, false));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
        }
    }
    // Class zero in another program (or flag mode) has different meaning.
    for (pattern, flags, expected) in [("[a]", "", true), ("[^a]", "", false), ("[A]", "", false), ("[A]", "i", true)] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        let mut run = Run::new(&regexp, &input, 1000);
        assert!(run.class_matches.entries.iter().all(Option::is_none));
        assert_eq!(run.class_matches.matches(&regexp, 0, 'a'), expected);
        assert_eq!(run.class_matches.evaluations, 1);
    }
}

#[test]
fn mixed_character_step_directions_and_caller_frames_remain_unchanged() {
    let mut regexp = BacktrackRegExp::new("[a-z]", "").unwrap();
    let input = PreparedInput::new("a!z");
    for backward in [false, true] {
        regexp.program = vec![super::super::Inst::Class { class: 0, backward }, super::super::Inst::Match];
        for start in 0..=input.char_len() {
            for budget in 0..=3 {
                let mut actual = Run::new(&regexp, &input, budget);
                let mut reference = Run::new(&regexp, &input, budget);
                reference.class_matches.disabled = true;
                let mut left = vec![super::super::Frame::Alternative { pc: usize::MAX, position: usize::MAX }];
                let mut right = vec![super::super::Frame::Alternative { pc: usize::MAX, position: usize::MAX }];
                assert_eq!(actual.execute(0, start, &mut left), reference.execute(0, start, &mut right));
                assert_eq!(actual.steps_left, reference.steps_left);
                assert_eq!(left.len(), 1);
                assert_eq!(right.len(), 1);
                assert!(matches!(left[0], super::super::Frame::Alternative { pc: usize::MAX, position: usize::MAX }));
            }
        }
    }
}

#[test]
fn prefix_rejections_share_membership_with_candidate_execution() {
    for (pattern, tail) in [
        (r"[a-z](?=!)", "a!"),
        (r"(?:[a-z]|[0-9])(?=!)", "5!"),
        (r"[\p{L}\p{N}_](?=!)", "a!"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, "u").unwrap();
        let input = PreparedInput::new(&format!("{}{tail}", "!".repeat(8192)));
        let mut actual = Run::new(&regexp, &input, 1_000_000);
        let mut reference = Run::new(&regexp, &input, 1_000_000);
        reference.class_matches.disabled = true;
        let result = actual.search(0, false).unwrap().expect("matching tail");
        assert_eq!(result[0], Some((8192, 8193)));
        assert_eq!(Some(result), reference.search(0, false).unwrap());
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(actual.candidate_executions, 1, "prefix must reject the long head");
        assert_eq!(actual.candidate_executions, reference.candidate_executions);
        assert!(actual.class_matches.evaluations <= regexp.classes.len() * 2 + 1, "{pattern}");
        assert!(actual.class_matches.hits >= 8191, "{pattern}");
        assert!(reference.class_matches.evaluations >= 8192, "{pattern}");
    }
}

#[test]
fn prefix_branches_collisions_and_nullable_exits_keep_refusal_state() {
    for (pattern, flags) in [
        (r"([a-z])(?=!)", ""),
        (r"(?:([a-z])|([0-9]))(?=!)", ""),
        (r"(?:[a]|[b]|[c]|[d]|[e]|[f])(?=!)", ""),
        (r"([a-z]?)(?=!)", "i"),
        (r"([a-z]??)(?=!)", "i"),
        (r"(?:[a-z]|)(?=!)", ""),
        (r"([a-z]+)\1(?=!)", "i"),
        (r"[^a-z](?=!)", "i"),
        (r"[\p{L}\p{N}_](?=!)", "u"),
        (r"(?:[\p{L}]|[\p{N}])(?=!)", "u"),
        (r"[a-z](?=!)", "iu"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in ["", "!", "!!a!", "!e!7!", "aBaB!", "!K!é!", "\0\n!a!"] {
            let input = PreparedInput::new(text);
            for start in 0..=input.char_len() + 1 {
                for budget in (0..=80).chain([127, 255, 4096]) {
                    for sticky in [false, true] {
                        compare(&regexp, &input, start, sticky, budget);
                    }
                }
            }
        }
    }
}

#[test]
fn prefix_affordability_and_eof_checks_precede_membership() {
    let regexp = BacktrackRegExp::new("[a-z]", "").unwrap();
    let input = PreparedInput::new("!a");
    let prefix = super::super::StartPrefix::new(&regexp).unwrap();
    let mut run = Run::new(&regexp, &input, 1);
    // Save(0) and Class cost two instructions. An unaffordable class must
    // not even populate the cache, and no candidate's writes are simulated.
    assert_eq!(run.skip_prefix_misses(0, &prefix), 0);
    assert_eq!(run.steps_left, 1);
    assert_eq!(run.class_matches.evaluations, 0);
    run.steps_left = 2;
    assert_eq!(run.skip_prefix_misses(0, &prefix), 1);
    assert_eq!(run.steps_left, 0);
    assert_eq!(run.class_matches.evaluations, 1);
    assert_eq!(run.skip_prefix_misses(1, &prefix), 0);
    assert_eq!(run.class_matches.evaluations, 1);
    run.steps_left = 1000;
    assert_eq!(run.skip_prefix_misses(input.char_len(), &prefix), 0);
    assert_eq!(run.class_matches.evaluations, 1);
    assert_eq!(run.steps_left, 1000);
    assert!(run.slots.iter().all(Option::is_none));
    assert_eq!(run.stack.capacity(), 0);
}

#[test]
fn successful_prefix_warms_execution_without_paying_its_instructions() {
    let regexp = BacktrackRegExp::new("[a-z]", "").unwrap();
    let input = PreparedInput::new("a");
    let prefix = super::super::StartPrefix::new(&regexp).unwrap();
    for budget in 2..=4 {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.class_matches.disabled = true;
        assert_eq!(actual.skip_prefix_misses(0, &prefix), 0);
        assert_eq!(actual.steps_left, budget, "no rejection was proved");
        assert_eq!(actual.class_matches.evaluations, 1);
        assert_eq!(actual.search(0, true), reference.search(0, true));
        assert_eq!(actual.steps_left, reference.steps_left);
        assert_eq!(actual.slots, reference.slots);
        assert_eq!(actual.registers, reference.registers);
        assert_eq!(actual.class_matches.evaluations, 1, "VM reuses prefix result");
        assert_eq!(actual.class_matches.hits, 1);
    }
}

#[test]
fn prefix_unicode_fallback_preserves_warm_ascii_bits() {
    let regexp = BacktrackRegExp::new(r"[a-z](?=!)", "iu").unwrap();
    let input = PreparedInput::new(&format!("!{}k!", "é".repeat(32)));
    let prefix = super::super::StartPrefix::new(&regexp).unwrap();
    let mut run = Run::new(&regexp, &input, 1_000_000);
    assert_eq!(run.skip_prefix_misses(0, &prefix), 33);
    assert_eq!(run.class_matches.evaluations, 34, "two ASCII values and 32 scalars");
    let before = run.class_matches.evaluations;
    let budget = run.steps_left;
    assert_eq!(run.skip_prefix_misses(0, &prefix), 33);
    assert_eq!(run.class_matches.evaluations - before, 32, "Unicode remains uncached");
    assert_eq!(budget - run.steps_left, 66, "same charge on warm/cold analysis");
    let before = run.class_matches.evaluations;
    assert_eq!(run.search(33, true).unwrap().unwrap()[0], Some((65, 66)));
    assert_eq!(run.class_matches.evaluations, before, "accepted k survives Unicode misses");
}

#[test]
fn prefix_and_execution_reuse_one_cache_across_searches_and_refusals() {
    let regexp = BacktrackRegExp::new(r"(?:([a-z]+)|([0-9]))(?=!)", "iu").unwrap();
    let input = PreparedInput::new("!!ab!7!K!e!");
    for budget in (0..=192).chain([1024]) {
        let mut actual = Run::new(&regexp, &input, budget);
        let mut reference = Run::new(&regexp, &input, budget);
        reference.class_matches.disabled = true;
        for (start, sticky) in [(0, false), (5, false), (7, true), (9, false), (0, true), (usize::MAX, false), (0, false)] {
            assert_eq!(actual.search(start, sticky), reference.search(start, sticky));
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert!(actual.stack.is_empty());
        }
    }
}
