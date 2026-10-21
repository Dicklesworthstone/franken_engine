use super::*;
use super::super::PreparedInput;

#[test]
fn unicode_blocks_cache_every_bit_of_the_complete_predicate() {
    for (pattern, flags) in [
        (r"\w", "iu"), (r"\W", "iu"), (r"\s", ""), (r"\S", ""),
        (r"\p{L}", "u"), (r"\P{L}", "u"), (r"[\p{L}\p{N}_]", "u"),
        (r"[^\p{Lu}\d]", "iu"), (r"[a-z]", "i"), (r"[a-z]", "iu"),
        ("[éÉΣσςKſ😀]", "u"), ("[^éÉΣσςKſ😀]", "iu"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        assert_eq!(regexp.classes.len(), 1);
        for block in [
            0x80_u32, 0xc0, 0x100, 0x300, 0x340, 0x380, 0x3c0, 0x400, 0x440,
            0x2000, 0x2100, 0x4e00, 0x65c0, 0x9fc0, 0xd7c0, 0xe000, 0xffc0,
            0x10000, 0x10400, 0x1f600, 0x10ffc0,
        ] {
            let mut cache = ClassMatches::default();
            for pass in 0..3 {
                for offset in 0..64 {
                    let offset = if pass == 1 { 63 - offset } else { offset };
                    let c = char::from_u32(block + offset).unwrap();
                    assert_eq!(
                        cache.matches(&regexp, 0, c),
                        regexp.class_matches(&regexp.classes[0], c),
                        "/{pattern}/{flags}, U+{:X}, pass={pass}", u32::from(c),
                    );
                }
            }
            assert_eq!(cache.evaluations, 64, "one evaluation per scalar, not per pass");
            assert_eq!(cache.hits, 128, "false membership must be cached too");
            assert!(cache.entries.iter().all(|entry| entry.known == [0; 2]));
        }
    }
}

#[test]
fn unicode_class_and_block_collisions_clear_both_membership_bitmaps() {
    let regexp = BacktrackRegExp::new("[é][^é][é][^é][é][^é][é][^é][é]", "u").unwrap();
    let mut cache = ClassMatches::default();
    // Same low six bits but distinct block and class identities. Blocks
    // separated by two and classes separated by two collide deliberately.
    for _ in 0..16 {
        for class in [0, 2, 4, 6, 8, 1, 3, 5, 7, 1, 0] {
            for scalar in [0xe9_u32, 0x169, 0x1e9, 0x10ffe9, 0xe9] {
                let c = char::from_u32(scalar).unwrap();
                let expected = regexp.class_matches(&regexp.classes[class], c);
                assert_eq!(cache.matches(&regexp, class, c), expected);
                let before = cache.evaluations;
                assert_eq!(cache.matches(&regexp, class, c), expected);
                assert_eq!(cache.evaluations, before);
            }
        }
    }
    assert_eq!(cache.unicode.len(), UNICODE_CACHE_SLOTS);
    assert!(std::mem::size_of::<ClassMatches>() <= 256);
}

#[test]
fn unicode_churn_never_evicts_ascii_and_two_blocks_stay_warm() {
    let regexp = BacktrackRegExp::new(r"[\p{L}][^\p{L}][\w][\W][\s][\S]", "iu").unwrap();
    let mut cache = ClassMatches::default();
    for class in 0..CACHE_SLOTS {
        for scalar in 0..128_u8 {
            cache.matches(&regexp, class, char::from(scalar));
        }
    }
    for scalar in (128..=0x10ffff_u32).step_by(257).filter_map(char::from_u32) {
        for class in 0..regexp.classes.len() {
            assert_eq!(cache.matches(&regexp, class, scalar),
                regexp.class_matches(&regexp.classes[class], scalar));
        }
    }
    let before = cache.evaluations;
    for class in 0..CACHE_SLOTS {
        for scalar in 0..128_u8 {
            let c = char::from(scalar);
            assert_eq!(cache.matches(&regexp, class, c),
                regexp.class_matches(&regexp.classes[class], c));
        }
    }
    assert_eq!(cache.evaluations, before, "Unicode cannot evict ASCII slots");
    let mut cache = ClassMatches::default();
    // Adjacent Greek blocks exercise both cache slots and the bit-63 edge.
    for _ in 0..128 {
        for scalar in 0x380..0x400_u32 {
            let c = char::from_u32(scalar).unwrap();
            assert_eq!(cache.matches(&regexp, 0, c),
                regexp.class_matches(&regexp.classes[0], c));
        }
    }
    assert_eq!(cache.evaluations, 128);
    assert_eq!(cache.hits, 127 * 128);
}

#[test]
fn unicode_execution_matches_uncached_state_at_refusal_boundaries() {
    for (pattern, flags) in [
        (r"(?=)([\p{L}]+)(?=!)", "u"),
        (r"(?=)([\p{L}]+?)(?=!)", "u"),
        (r"(?=)([^\p{Lu}]{0,32}?)(?=!)", "iu"),
        (r"(?<=([\p{L}]{0,32}))!", "u"),
        (r"(?<=([\p{L}]*?))!", "iu"),
        (r"(?=)([éΣ]+)\1(?=!)", "iu"),
        (r"(?=)(([éΣ])|([^éΣ]))+!", "u"),
        (r"(?:[é]|[Σ]|[Ж]|[😀]|[é])(?=!)", "u"),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).expect(pattern);
        for text in ["", "!", "éÉé!", "Σσς!", "éΣéΣ!", "Ж😀é!", "Kkſs!"] {
            let input = PreparedInput::new(text);
            for budget in (0..=96).chain([127, 255, 4096]) {
                for sticky in [false, true] {
                    let mut actual = Run::new(&regexp, &input, budget);
                    let mut reference = Run::new(&regexp, &input, budget);
                    reference.class_matches.disabled = true;
                    // Reuse the same operation and its remaining allowance,
                    // including after errors and out-of-range starts.
                    for start in [0, 1, input.char_len(), 0, usize::MAX] {
                        assert_eq!(actual.search(start, sticky), reference.search(start, sticky),
                            "/{pattern}/{flags} {text:?} {start} {sticky} {budget}");
                        assert_eq!(actual.steps_left, reference.steps_left);
                        assert_eq!(actual.slots, reference.slots);
                        assert_eq!(actual.registers, reference.registers);
                        assert!(actual.stack.is_empty());
                        assert!(actual.capture_seen.iter().all(|seen| !seen));
                    }
                }
            }
        }
    }
}

#[test]
fn long_unicode_repetitions_reuse_predicates_in_all_loop_forms() {
    for pattern in [
        r"(?=)([éΣЖ😀]+)(?=!)", r"(?=)([éΣЖ😀]+?)(?=!)",
        r"(?=)([éΣЖ😀]{0,10000})(?=!)", r"(?=)([éΣЖ😀]{0,10000}?)(?=!)",
        r"(?=)([éΣЖ😀]{4096})(?=!)", r"(?=)([éΣЖ😀])+(?=!)",
    ] {
        let regexp = BacktrackRegExp::new(pattern, "u").unwrap();
        for c in ['é', 'Σ', 'Ж', '😀'] {
            let input = PreparedInput::new(&format!("{}!", c.to_string().repeat(4096)));
            let mut actual = Run::new(&regexp, &input, 1_000_000);
            let mut reference = Run::new(&regexp, &input, 1_000_000);
            reference.class_matches.disabled = true;
            let result = actual.search(0, true).unwrap().expect("matching Unicode run");
            assert_eq!(result[0], Some((0, c.len_utf8() * 4096)));
            assert_eq!(Some(result), reference.search(0, true).unwrap());
            assert_eq!(actual.steps_left, reference.steps_left);
            assert_eq!(actual.slots, reference.slots);
            assert_eq!(actual.registers, reference.registers);
            assert!(actual.class_matches.evaluations <= 2, "{pattern}");
            assert!(actual.class_matches.hits >= 4095, "{pattern}");
            assert!(reference.class_matches.evaluations >= 4096, "{pattern}");
        }
    }
}

#[test]
fn unicode_prefix_refusals_and_new_programs_never_inherit_membership() {
    let regexp = BacktrackRegExp::new(r"[a-z](?=!)", "iu").unwrap();
    let input = PreparedInput::new("ééK!");
    let prefix = super::super::StartPrefix::new(&regexp).unwrap();
    let mut run = Run::new(&regexp, &input, 1);
    assert_eq!(run.skip_prefix_misses(0, &prefix), 0);
    assert_eq!(run.steps_left, 1);
    assert_eq!(run.class_matches.evaluations, 0);
    assert!(run.class_matches.unicode.iter().all(|entry| entry.known == 0));
    run.steps_left = 4;
    assert_eq!(run.skip_prefix_misses(0, &prefix), 2);
    assert_eq!(run.steps_left, 0);
    assert_eq!(run.class_matches.evaluations, 1);
    assert_eq!(run.class_matches.hits, 1);
    run.steps_left = 1000;
    let before = run.class_matches.evaluations;
    assert_eq!(run.skip_prefix_misses(input.char_len(), &prefix), 0);
    assert_eq!(run.class_matches.evaluations, before);
    for (pattern, flags, expected) in [
        ("[é]", "u", true), ("[^é]", "u", false),
        ("[É]", "u", false), ("[É]", "iu", true),
    ] {
        let regexp = BacktrackRegExp::new(pattern, flags).unwrap();
        let mut run = Run::new(&regexp, &input, 1000);
        assert!(run.class_matches.unicode.iter().all(|entry| entry.known == 0));
        assert_eq!(run.class_matches.matches(&regexp, 0, 'é'), expected);
        assert_eq!(run.class_matches.evaluations, 1);
        assert_eq!(run.class_matches.matches(&regexp, 0, 'é'), expected);
        assert_eq!(run.class_matches.evaluations, 1);
    }
}
