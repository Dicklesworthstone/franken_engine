use super::*;

fn rope(left: JsString, right: JsString) -> JsString {
    assert!(left.is_well_formed() && right.is_well_formed());
    let shape = left.joined_shape(&right);
    JsString::joined(left, right, shape)
}

fn pair(left: &str, right: &str) -> JsString {
    rope(JsString::from(left), JsString::from(right))
}

fn assert_unjoined(value: &JsString) {
    let Text::Concat(node) = &value.utf8 else {
        panic!("test requires a rope");
    };
    assert!(node.joined.get().is_none(), "search materialized the rope");
}

fn reference_first(haystack: &[u16], needle: &[u16], from: usize) -> Option<usize> {
    let from = from.min(haystack.len());
    if needle.is_empty() {
        return Some(from);
    }
    if needle.len() > haystack.len() - from {
        return None;
    }
    (from..=haystack.len() - needle.len())
        .find(|&index| &haystack[index..index + needle.len()] == needle)
}

fn reference_last(haystack: &[u16], needle: &[u16], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from.min(haystack.len()));
    }
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=from.min(haystack.len() - needle.len()))
        .rev()
        .find(|&index| &haystack[index..index + needle.len()] == needle)
}

fn assert_searches(haystack: &JsString, needle: &JsString, positions: &[usize]) {
    let haystack_units = haystack.code_units_vec();
    let needle_units = needle.code_units_vec();
    for &from in positions {
        assert_eq!(
            haystack.utf16_index_of(needle, from),
            reference_first(&haystack_units, &needle_units, from),
            "indexOf units={haystack_units:?}, needle={needle_units:?}, from={from}"
        );
        assert_eq!(
            haystack.utf16_last_index_of(needle, from),
            reference_last(&haystack_units, &needle_units, from),
            "lastIndexOf units={haystack_units:?}, needle={needle_units:?}, from={from}"
        );
        assert_unjoined(haystack);
    }
}

#[test]
fn searches_match_exact_units_at_every_small_boundary() {
    let pieces = ["", "a", "aba", "\u{e9}", "\u{65e5}", "\u{1f600}", "a\u{1f600}a"];
    let needles = [
        vec![],
        vec![0x61],
        vec![0x61, 0x62, 0x61],
        vec![0xe9],
        vec![0x65e5],
        vec![0xd83d],
        vec![0xde00],
        vec![0xd83d, 0xde00],
        vec![0xde00, 0x61],
        vec![0x61, 0xd83d],
        vec![0xd800],
        vec![0xdc00],
        vec![0xfffd],
        vec![0x7a; 32],
    ];
    for left in pieces {
        for right in pieces {
            let value = pair(left, right);
            let mut positions: Vec<usize> = (0..=value.utf16_len() + 1).collect();
            positions.push(usize::MAX);
            for needle in &needles {
                assert_searches(&value, &JsString::from_code_units(needle), &positions);
            }
        }
    }
}

#[test]
fn matches_cross_multiple_leaves_and_keep_overlaps() {
    let haystack = rope(pair("ab", "ab"), pair("ab", "aba"));
    let needle = pair("ab", "aba");
    assert_eq!(haystack.utf16_index_of(&needle, 0), Some(0));
    assert_eq!(haystack.utf16_last_index_of(&needle, usize::MAX), Some(4));
    assert_eq!(haystack.utf16_last_index_of(&needle, 3), Some(2));
    let positions: Vec<_> = (0..=haystack.utf16_len() + 1).collect();
    assert_searches(&haystack, &needle, &positions);
    assert_unjoined(&needle);
}

#[test]
fn reverse_position_bounds_the_start_not_the_end() {
    let haystack = pair("pre-ab", "c-post-abc");
    let needle = JsString::from("abc");
    assert_eq!(haystack.utf16_last_index_of(&needle, 4), Some(4));
    assert_eq!(haystack.utf16_last_index_of(&needle, 3), None);
    assert_searches(&haystack, &needle, &[0, 3, 4, 5, 12, usize::MAX]);
}

#[test]
fn reverse_units_match_every_consumed_prefix_and_skip() {
    for left in ["", "a", "\u{e9}", "\u{65e5}", "\u{1f600}", "a\u{1f600}z"] {
        for right in ["", "a", "\u{1f600}", "\u{1f600}\u{10ffff}z"] {
            let value = pair(left, right);
            let expected: Vec<u16> = value.encode_utf16().collect();
            for consumed in 0..=expected.len() {
                for skip in 0..=expected.len() + 1 {
                    let mut actual = ReverseUnits::new(&value);
                    let mut reference = expected.iter().rev().copied();
                    for _ in 0..consumed {
                        assert_eq!(actual.next(), reference.next());
                    }
                    assert_eq!(actual.nth(skip), reference.nth(skip));
                    assert_eq!(actual.collect::<Vec<_>>(), reference.collect::<Vec<_>>());
                }
            }
            let mut exhausted = ReverseUnits::new(&value);
            assert_eq!(exhausted.nth(usize::MAX), None);
            assert_eq!(exhausted.next(), None);
            assert_unjoined(&value);
        }
    }
}

#[test]
fn reverse_leaf_seek_handles_ascii_bmp_and_mixed_unicode() {
    for text in [
        "a".repeat(4096),
        "\u{65e5}".repeat(4096),
        "\u{e9}a\u{1f600}\u{20ac}\u{10ffff}".repeat(512),
        format!("\u{1f600}{}\u{e9}", "x".repeat(8192)),
    ] {
        let value = pair("prefix\u{1f600}", &text);
        let expected = value.code_units_vec();
        for consumed in [0, 1, 2, 3, 31] {
            for skip in [0, 1, 2, 31, 256, expected.len() / 2, expected.len() - 32] {
                let mut actual = ReverseUnits::new(&value);
                let mut reference = expected.iter().rev().copied();
                for _ in 0..consumed {
                    assert_eq!(actual.next(), reference.next());
                }
                assert_eq!(actual.nth(skip), reference.nth(skip));
                assert_eq!(actual.collect::<Vec<_>>(), reference.collect::<Vec<_>>());
            }
        }
        assert_unjoined(&value);
    }
}

#[test]
fn suffix_match_does_not_visit_or_flatten_the_accumulated_prefix() {
    let mut prefix = JsString::from("x".repeat(1024));
    for _ in 0..13 {
        prefix = rope(prefix.clone(), prefix);
    }
    let value = rope(prefix.clone(), JsString::from("\u{1f600}needle"));
    let mut reverse = ReverseUnits::new(&value);
    let suffix: Vec<_> = reverse.by_ref().take(6).collect();
    assert_eq!(suffix, "needle".bytes().rev().map(u16::from).collect::<Vec<_>>());
    assert_eq!(reverse.visited_nodes, 1);
    assert_eq!(reverse.decoded_scalars, 6);
    assert_eq!(
        value.utf16_last_index_of(&JsString::from("needle"), usize::MAX),
        Some(prefix.utf16_len() + 2)
    );
    assert_unjoined(&value);
    assert_unjoined(&prefix);
}

#[test]
fn bounded_reverse_search_skips_an_entire_suffix_subtree() {
    let mut suffix = JsString::from("x".repeat(1024));
    for _ in 0..13 {
        suffix = rope(suffix.clone(), suffix);
    }
    let value = rope(JsString::from("a\u{1f600}"), suffix.clone());
    let mut reverse = ReverseUnits::new(&value);
    assert_eq!(reverse.nth(suffix.utf16_len()), Some(0xde00));
    assert_eq!(reverse.next(), Some(0xd83d));
    assert_eq!(reverse.next(), Some(0x61));
    assert_eq!(reverse.next(), None);
    assert_eq!(reverse.visited_nodes, 1);
    assert_eq!(reverse.decoded_scalars, 2);
    let high = JsString::from_code_units(&[0xd83d]);
    assert_eq!(value.utf16_last_index_of(&high, 1), Some(1));
    assert_unjoined(&value);
    assert_unjoined(&suffix);
}

#[test]
fn append_then_search_keeps_each_growing_result_unjoined() {
    let piece = JsString::from("abcdefghijklmnopqrstuvwxyz::needle");
    let needle = JsString::from("needle");
    let mut value = JsString::from("prefix".repeat(256));
    for _ in 0..2048 {
        value = value.concat(&piece);
        assert_eq!(
            value.utf16_last_index_of(&needle, usize::MAX),
            Some(value.utf16_len() - needle.utf16_len())
        );
        assert_unjoined(&value);
    }
}

#[test]
fn publication_between_reverse_reads_keeps_owned_children_valid() {
    let left = pair("ab", "\u{1f600}");
    let right = pair("\u{65e5}", "\u{10ffff}");
    let value = rope(left.clone(), right.clone());
    let expected = value.code_units_vec();
    let mut actual = ReverseUnits::new(&value);
    assert_eq!(actual.next(), expected.last().copied());
    // Publish and release children with both pending subtrees and a buffered
    // surrogate in the reader. Its owned leaf remains exact and alive.
    let _ = value.as_utf8_projection();
    let _ = left.as_utf8_projection();
    let _ = right.as_utf8_projection();
    assert_eq!(
        actual.collect::<Vec<_>>(),
        expected[..expected.len() - 1].iter().rev().copied().collect::<Vec<_>>()
    );
    assert_eq!(
        ReverseUnits::new(&value).collect::<Vec<_>>(),
        expected.iter().rev().copied().collect::<Vec<_>>()
    );
}

#[test]
fn concurrent_publication_preserves_search_results() {
    use std::sync::Barrier;

    for _ in 0..32 {
        let value = rope(pair("prefix", "\u{1f600}"), pair("needle", "\u{10ffff}"));
        let shared = value.clone();
        let barrier = Arc::new(Barrier::new(2));
        let other_barrier = Arc::clone(&barrier);
        let worker = std::thread::spawn(move || {
            other_barrier.wait();
            shared.as_utf8_projection().to_owned()
        });
        barrier.wait();
        assert_eq!(value.utf16_index_of(&JsString::from("needle"), 0), Some(8));
        assert_eq!(
            value.utf16_last_index_of(&JsString::from("needle"), usize::MAX),
            Some(8)
        );
        assert_eq!(worker.join().unwrap(), "prefix\u{1f600}needle\u{10ffff}");
    }
}

#[test]
fn deterministic_mixed_unicode_searches_match_reference() {
    let mut seed = 0x91d3_1a4bu32;
    let mut next = || {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        seed
    };
    let alphabet = ['a', 'b', '\u{e9}', '\u{65e5}', '\u{1f600}', '\u{10ffff}'];
    for _ in 0..128 {
        let mut leaves = Vec::new();
        for _ in 0..8 {
            let text: String = (0..next() % 9)
                .map(|_| alphabet[next() as usize % alphabet.len()])
                .collect();
            leaves.push(JsString::from(text));
        }
        while leaves.len() > 1 {
            let mut level = Vec::new();
            for pair in leaves.as_chunks::<2>().0 {
                level.push(rope(pair[0].clone(), pair[1].clone()));
            }
            leaves = level;
        }
        let value = leaves.pop().unwrap();
        let units = value.code_units_vec();
        for _ in 0..16 {
            let start = next() as usize % (units.len() + 1);
            let end = (start + next() as usize % 9).min(units.len());
            let needle = JsString::from_code_units(&units[start..end]);
            let from = next() as usize % (units.len() + 2);
            assert_searches(&value, &needle, &[0, from, start, end, usize::MAX]);
        }
        assert_searches(&value, &JsString::from_code_units(&[0xd800]), &[0, usize::MAX]);
    }
}

#[test]
#[ignore = "release-mode experiment; reports timings, not a performance assertion"]
fn append_search_release_experiment() {
    use std::hint::black_box;
    use std::time::Instant;

    for appends in [512, 2048, 8192] {
        for materialize in [false, true] {
            let piece = JsString::from("abcdefghijklmnopqrstuvwxyz::needle");
            let needle = JsString::from("needle");
            let mut value = JsString::from("prefix".repeat(256));
            let start = Instant::now();
            for _ in 0..appends {
                value = value.concat(&piece);
                if materialize {
                    // Reproduce the old eager-read path; the search then uses
                    // the unchanged native reverse byte-search branch.
                    black_box(value.as_utf8_projection());
                }
                assert_eq!(
                    black_box(value.utf16_last_index_of(black_box(&needle), usize::MAX)),
                    Some(value.utf16_len() - needle.utf16_len())
                );
            }
            println!(
                "appends={appends} materialize={materialize} elapsed_ns={} bytes={}",
                start.elapsed().as_nanos(),
                value.len()
            );
        }
    }
}
