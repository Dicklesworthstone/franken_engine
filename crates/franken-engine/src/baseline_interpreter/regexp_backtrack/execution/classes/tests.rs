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
