use super::*;

fn rope(left: JsString, right: JsString) -> JsString {
    let shape = left.joined_shape(&right);
    JsString::joined(left, right, shape)
}

fn unjoined(text: &JsString) {
    let Text::Concat(node) = &text.utf8 else { panic!("expected rope") };
    assert!(node.joined.get().is_none(), "search must not publish a flat copy");
}

fn check(haystack: &JsString, needle: &JsString) {
    let text = haystack.code_units_vec();
    let pattern = needle.code_units_vec();
    for from in (0..=text.len() + 1).chain([usize::MAX]) {
        let start = from.min(text.len());
        let first = if pattern.is_empty() {
            Some(start)
        } else if pattern.len() > text.len() - start {
            None
        } else {
            (start..=text.len() - pattern.len())
                .find(|&i| text[i..i + pattern.len()] == pattern)
        };
        let last = if pattern.is_empty() {
            Some(start)
        } else if pattern.len() > text.len() {
            None
        } else {
            (0..=start.min(text.len() - pattern.len())).rev()
                .find(|&i| text[i..i + pattern.len()] == pattern)
        };
        assert_eq!(haystack.utf16_index_of(needle, from), first, "forward {text:?} {pattern:?} {from}");
        assert_eq!(haystack.utf16_last_index_of(needle, from), last, "reverse {text:?} {pattern:?} {from}");
    }
    unjoined(haystack);
}

#[test]
fn preparation_does_not_publish_or_project_the_needle() {
    for text in ["a", "é", "日", "😀"] {
        let needle = JsString::from(text);
        assert_eq!(pattern(&needle).as_deref(), Some(text));
        assert!(matches!(pattern(&needle), Some(Cow::Borrowed(_))));
    }
    assert!(pattern(&JsString::from("")).is_none());
    assert!(pattern(&JsString::from("x".repeat(64))).is_some());
    assert!(pattern(&JsString::from("x".repeat(65))).is_some());
    assert!(pattern(&JsString::from_code_units(&[0xd800])).is_none());
    assert!(pattern(&JsString::from("�")).is_some());
    let needle = rope(JsString::from("ab"), JsString::from("cd"));
    assert!(matches!(pattern(&needle), Some(Cow::Owned(_))));
    assert_eq!(pattern(&needle).as_deref(), Some("abcd"));
    unjoined(&needle);
    let _ = needle.as_utf8_projection();
    assert_eq!(pattern(&needle).as_deref(), Some("abcd"));
    assert!(matches!(pattern(&needle), Some(Cow::Borrowed(_))));
}

#[test]
fn mixed_unicode_bounds_and_exact_only_fallback_match_unit_oracle() {
    let pieces = ["", "a", "aba", "é", "日", "😀", "a😀a"];
    for left in pieces {
        for right in pieces {
            let text = rope(JsString::from(left), JsString::from(right));
            for needle in ["", "a", "aba", "é", "日", "😀", "a😀", "😀a", "�", "absent"] {
                check(&text, &JsString::from(needle));
            }
            for units in [&[0xd83d][..], &[0xde00], &[0xde00, 0x61], &[0x61, 0xd83d]] {
                check(&text, &JsString::from_code_units(units));
            }
        }
    }
}

#[test]
fn matches_cross_many_small_leaves_without_losing_overlaps() {
    for text in ["abababababa", "é日😀é日😀é", "aaaaaaaaaaaaaaaaabaaaaab"] {
        let mut value = rope(JsString::from(""), JsString::from(""));
        for scalar in text.chars() {
            value = rope(value, JsString::from(scalar.to_string()));
        }
        for needle in ["ababa", "é日😀é", "aaaaab", "😀é", "missing"] {
            check(&value, &JsString::from(needle));
        }
    }
}

#[test]
fn crossing_matches_precede_local_matches_in_both_directions() {
    let forward = rope(JsString::from(format!("{}ab", "x".repeat(256))),
        JsString::from(format!("c{}abc", "x".repeat(256))));
    assert_eq!(forward.utf16_index_of(&JsString::from("abc"), 0), Some(256));
    let backwards = rope(JsString::from(format!("abc{}ab", "x".repeat(256))),
        JsString::from(format!("c{}", "x".repeat(256))));
    assert_eq!(backwards.utf16_last_index_of(&JsString::from("abc"), usize::MAX), Some(259));
    unjoined(&forward);
    unjoined(&backwards);
}

#[test]
fn large_leaf_search_leaves_only_bounded_scalar_match_work() {
    for backwards in [false, true] {
        let mut matcher = Matcher::new("ababac", backwards);
        let text = "ab".repeat(524_288);
        assert!(matcher.in_leaf(&text).is_none());
        assert!(matcher.fed_bytes < 2 * matcher.text.len());
        let before = matcher.fed_bytes;
        assert!(matcher.in_leaf(&text).is_none());
        assert!(matcher.fed_bytes - before < 2 * matcher.text.len());
        let mut one = Matcher::new("z", backwards);
        assert!(one.in_leaf(&text).is_none());
        assert_eq!(one.fed_bytes, 0, "single-byte leaf misses use bulk search only");
    }
}

#[test]
fn bounds_and_early_hits_skip_shared_gigabyte_subtrees() {
    let mut huge = JsString::from("x".repeat(1024));
    for _ in 0..20 { huge = rope(huge.clone(), huge); }
    let value = rope(huge.clone(), JsString::from("😀needle"));
    let start = huge.utf16_len();
    for backwards in [false, true] {
        let mut leaves = Leaves::new(&value, start, value.utf16_len(), backwards);
        let leaf = leaves.next().unwrap();
        assert_eq!(&*leaf.text, "😀needle");
        assert_eq!(leaf.unit_start, start);
        assert!(leaves.next().is_none());
        assert_eq!(leaves.visited, 2, "root plus chosen leaf only");
    }
    assert_eq!(value.utf16_index_of(&JsString::from("needle"), start), Some(start + 2));
    assert_eq!(value.utf16_last_index_of(&JsString::from("needle"), usize::MAX), Some(start + 2));
    let head = rope(JsString::from("needle😀"), huge.clone());
    assert_eq!(head.utf16_index_of(&JsString::from("needle"), 0), Some(0));
    assert_eq!(head.utf16_last_index_of(&JsString::from("needle"), 0), Some(0));
    unjoined(&value);
    unjoined(&head);
    unjoined(&huge);
}

#[test]
fn directional_matcher_agrees_for_every_pattern_width() {
    for width in (1..=INLINE_PATTERN_BYTES).chain([65, 80, 127, 128, 255, 256, 1024, 4097]) {
        let needle = format!("{}b", "a".repeat(width - 1));
        let haystack = format!("{}{}{}{}", "a".repeat(129), needle, "a".repeat(131), needle);
        for chunk in [1, 2, 7, 63, 64, 65, 129, 1024] {
            let pieces: Vec<&str> = haystack.as_bytes().chunks(chunk)
                .map(|bytes| std::str::from_utf8(bytes).unwrap()).collect();
            for backwards in [false, true] {
                let mut matcher = Matcher::new(&needle, backwards);
                let mut boundary = if backwards { haystack.len() } else { 0 };
                let mut result = None;
                let ordered: Vec<_> = if backwards { pieces.iter().rev().copied().collect() }
                    else { pieces.clone() };
                for piece in ordered {
                    let start = if backwards { boundary - piece.len() } else { boundary };
                    if let Some(found) = matcher.in_leaf(piece) {
                        result = Some(match found {
                            LeafMatch::Local(byte) => start + byte,
                            LeafMatch::Consumed(bytes) if backwards => boundary - bytes,
                            LeafMatch::Consumed(bytes) => start + bytes - needle.len(),
                        });
                        break;
                    }
                    boundary = if backwards { start } else { boundary + piece.len() };
                }
                let expected = if backwards { haystack.rfind(&needle) } else { haystack.find(&needle) };
                assert_eq!(result, expected, "width={width} chunk={chunk} backwards={backwards}");
            }
        }
    }
}

#[test]
fn long_needles_and_unjoined_needles_preserve_streaming_semantics() {
    let value = rope(JsString::from("a".repeat(96)), JsString::from("b".repeat(96)));
    for width in [63, 64, 65, 80] {
        check(&value, &JsString::from(format!("{}b", "a".repeat(width - 1))));
    }
    let needle = rope(JsString::from("aaa"), JsString::from("bbb"));
    check(&value, &needle);
    unjoined(&needle);
}

#[test]
fn leaf_references_survive_publication_with_pending_children() {
    for backwards in [false, true] {
        let left = rope(JsString::from("é"), JsString::from("😀"));
        let right = rope(JsString::from("日"), JsString::from("needle"));
        let value = rope(left.clone(), right.clone());
        let mut leaves = Leaves::new(&value, 0, value.utf16_len(), backwards);
        let first = leaves.next().unwrap();
        let _ = value.as_utf8_projection();
        let _ = left.as_utf8_projection();
        let _ = right.as_utf8_projection();
        let mut collected = vec![(first.unit_start, first.text)];
        collected.extend(leaves.map(|leaf| (leaf.unit_start, leaf.text)));
        collected.sort_by_key(|(start, _)| *start);
        let text: String = collected.iter().map(|(_, text)| &**text).collect();
        assert_eq!(text, "é😀日needle");
    }
}

#[test]
fn long_unicode_needles_preserve_every_utf16_start_boundary() {
    for repeated in ["é", "日", "😀", "a😀日"] {
        let spelling = format!("{}b", repeated.repeat(33));
        let needle = JsString::from(spelling.clone());
        assert!(pattern(&needle).is_some());
        for split in spelling
            .char_indices()
            .map(|(byte, _)| byte)
            .step_by(11)
        {
            let value = rope(
                JsString::from(format!("😀{}", &spelling[..split])),
                JsString::from(format!("{}😀{spelling}", &spelling[split..])),
            );
            check(&value, &needle);
        }
    }
}

#[test]
fn long_pattern_failure_storage_is_needle_sized() {
    for width in [1, 64, 65, 1024, 4097] {
        let text = "a".repeat(width);
        let mut matcher = Matcher::new(&text, false);
        assert!(matcher.failure.is_none());
        matcher.prepare_failure();
        let failure = matcher.failure.as_ref().unwrap();
        if width <= INLINE_PATTERN_BYTES {
            assert!(failure.overflow.is_empty());
            assert_eq!(failure.as_slice().len(), INLINE_PATTERN_BYTES);
        } else {
            assert_eq!(failure.overflow.len(), width);
        }
        assert_eq!(failure.as_slice()[width - 1], width - 1);
    }
}

#[test]
fn long_patterns_keep_large_leaf_matching_out_of_the_scalar_loop() {
    let text = "ab".repeat(524_288);
    for width in [65, 128, 1024] {
        let needle = format!("{}z", "a".repeat(width - 1));
        for backwards in [false, true] {
            let mut matcher = Matcher::new(&needle, backwards);
            for _ in 0..2 {
                let before = matcher.fed_bytes;
                assert!(matcher.in_leaf(&text).is_none());
                assert!(matcher.fed_bytes - before < 2 * width);
            }
        }
    }
}

#[test]
fn leaf_local_hits_do_not_build_any_failure_table() {
    for width in [1, 64, 65, 1024, 4097] {
        let needle = format!("{}z", "a".repeat(width - 1));
        let leaf = format!("{}{}{}", "x".repeat(width), needle, "x".repeat(width));
        for backwards in [false, true] {
            let mut matcher = Matcher::new(&needle, backwards);
            assert!(matches!(matcher.in_leaf(&leaf), Some(LeafMatch::Local(index)) if index == width));
            assert!(matcher.failure.is_none(), "a local hit must not prepare a table");
            assert_eq!(matcher.fed_bytes, 0);
        }
    }
}

#[test]
fn empty_leaves_and_one_byte_bulk_misses_do_not_prepare_tables() {
    for backwards in [false, true] {
        let mut matcher = Matcher::new("z", backwards);
        assert!(matcher.in_leaf("").is_none());
        assert!(matcher.in_leaf(&"a".repeat(65_536)).is_none());
        assert!(matcher.failure.is_none());
        assert_eq!(matcher.fed_bytes, 0);
    }
}

#[test]
fn lazily_prepared_table_is_reused_across_small_leaves() {
    let needle = format!("{}z", "a".repeat(127));
    for backwards in [false, true] {
        let mut matcher = Matcher::new(&needle, backwards);
        assert!(matcher.in_leaf("x").is_none());
        let table = matcher.failure.as_ref().unwrap().overflow.as_ptr();
        for _ in 0..32 {
            assert!(matcher.in_leaf("a").is_none());
            assert_eq!(matcher.failure.as_ref().unwrap().overflow.as_ptr(), table);
        }
    }
}

#[test]
fn lazy_long_crossing_match_still_precedes_a_leaf_local_match() {
    let needle = format!("{}z", "a".repeat(127));
    let mut forward = Matcher::new(&needle, false);
    assert!(forward.in_leaf(&"a".repeat(127)).is_none());
    let leaf = format!("z{}{needle}", "x".repeat(512));
    assert!(matches!(forward.in_leaf(&leaf), Some(LeafMatch::Consumed(1))));

    let mut backwards = Matcher::new(&needle, true);
    assert!(backwards.in_leaf("z").is_none());
    let leaf = format!("{needle}{}{}", "x".repeat(512), "a".repeat(127));
    assert!(matches!(backwards.in_leaf(&leaf), Some(LeafMatch::Consumed(127))));
}

#[test]
fn rope_needles_use_byte_search_without_publishing_either_input() {
    for unit in ["a", "é", "日", "😀", "a😀日"] {
        let prefix = unit.repeat(33);
        let needle = rope(JsString::from(prefix.clone()), JsString::from("z"));
        let value = rope(
            JsString::from(format!("😀{prefix}")),
            JsString::from(format!("z{prefix}z😀")),
        );
        assert!(matches!(pattern(&needle), Some(Cow::Owned(_))));
        check(&value, &needle);
        unjoined(&needle);
    }
}

#[test]
fn shared_subtree_needles_keep_every_logical_occurrence() {
    let part = rope(JsString::from("é😀"), JsString::from("日"));
    let doubled = rope(part.clone(), part.clone());
    let needle = rope(doubled.clone(), doubled.clone());
    let spelling = "é😀日".repeat(4);
    let prepared = pattern(&needle).unwrap();
    assert_eq!(prepared.as_ref(), spelling);
    assert!(matches!(&prepared, Cow::Owned(_)));
    unjoined(&part);
    unjoined(&doubled);
    unjoined(&needle);
    let value = rope(JsString::from(format!("x{spelling}")), JsString::from(spelling));
    check(&value, &needle);
    // A published root and children must not invalidate already-owned bytes.
    let _ = needle.as_utf8_projection();
    let _ = part.as_utf8_projection();
    assert_eq!(prepared.as_ref(), "é😀日".repeat(4));
}

#[test]
fn rope_needle_early_hits_skip_a_shared_gigabyte_haystack() {
    let mut huge = JsString::from("x".repeat(1024));
    for _ in 0..20 {
        huge = rope(huge.clone(), huge);
    }
    let needle = rope(JsString::from("long".repeat(40)), JsString::from("😀needle"));
    let start = huge.utf16_len();
    let tail = rope(huge.clone(), needle.clone());
    let head = rope(needle.clone(), huge.clone());
    assert_eq!(tail.utf16_index_of(&needle, start), Some(start));
    assert_eq!(tail.utf16_last_index_of(&needle, usize::MAX), Some(start));
    assert_eq!(head.utf16_index_of(&needle, 0), Some(0));
    assert_eq!(head.utf16_last_index_of(&needle, 0), Some(0));
    unjoined(&tail);
    unjoined(&head);
    unjoined(&needle);
    unjoined(&huge);
}
