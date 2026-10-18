use super::*;

#[test]
fn leading_misses_do_not_prepare_a_megabyte_needle() {
    let needle = "a".repeat(1 << 20);
    for backwards in [false, true] {
        let mut matcher = Matcher::new(&needle, backwards);
        for _ in 0..256 {
            assert!(matcher.scan(b"xxxxxxxxxxxxxxxx").is_none());
        }
        assert!(matcher.failure.is_none());
        assert_eq!(matcher.matched, 0);
        assert_eq!(matcher.fed_bytes, 4096);
    }
}

#[test]
fn uninterrupted_cross_leaf_matches_need_no_failure_table() {
    for repetitions in [1, 8, 65, 1024] {
        let needle = format!("{}z", "a\u{e9}\u{65e5}\u{1f600}".repeat(repetitions));
        for chunk in [1, 2, 7, 64, 129] {
            for backwards in [false, true] {
                let mut matcher = Matcher::new(&needle, backwards);
                assert_eq!(matcher.scan(b"xxxx"), None);
                let mut consumed = 0;
                let mut remaining = needle.as_bytes();
                while !remaining.is_empty() {
                    let count = chunk.min(remaining.len());
                    let (piece, rest) = if backwards {
                        (&remaining[remaining.len() - count..], &remaining[..remaining.len() - count])
                    } else {
                        (&remaining[..count], &remaining[count..])
                    };
                    let found = matcher.scan(piece);
                    consumed += count;
                    assert_eq!(found, (rest.is_empty()).then_some(count));
                    assert!(matcher.failure.is_none());
                    assert_eq!(matcher.scan(b""), None);
                    assert!(matcher.failure.is_none());
                    remaining = rest;
                }
                assert_eq!(consumed, needle.len());
                assert_eq!(matcher.fed_bytes, needle.len() + 4);
            }
        }
    }
}

#[test]
fn first_fallback_reuses_the_mismatch_byte_without_double_counting() {
    for needle in ["ababa", "aaaaab", "abacaba", "\u{e9}\u{65e5}\u{e9}"] {
        let text = format!("xxx{needle}{needle}ababacaaaaababax{needle}");
        for backwards in [false, true] {
            for chunk in [1, 3, 9, 64] {
                let mut lazy = Matcher::new(needle, backwards);
                let mut eager = Matcher::new(needle, backwards);
                eager.prepare_failure();
                let mut remaining = text.as_bytes();
                while !remaining.is_empty() {
                    let count = chunk.min(remaining.len());
                    let piece = if backwards {
                        &remaining[remaining.len() - count..]
                    } else {
                        &remaining[..count]
                    };
                    let actual = lazy.scan(piece);
                    assert_eq!(actual, eager.scan(piece));
                    let consumed = actual.unwrap_or(count);
                    assert!(consumed > 0);
                    assert_eq!(lazy.fed_bytes, eager.fed_bytes);
                    remaining = if backwards {
                        &remaining[..remaining.len() - consumed]
                    } else {
                        &remaining[consumed..]
                    };
                }
            }
        }
    }
}

#[test]
fn complete_match_can_resume_with_overlaps_in_either_direction() {
    for width in [1, 2, 64, 65, 129] {
        let needle = "a".repeat(width);
        for backwards in [false, true] {
            let mut matcher = Matcher::new(&needle, backwards);
            assert_eq!(matcher.scan(needle.as_bytes()), Some(width));
            assert!(matcher.failure.is_none());
            for _ in 0..8 {
                assert_eq!(matcher.scan(b""), None);
                assert_eq!(matcher.scan(b"a"), Some(1));
            }
            assert!(matcher.failure.is_some());
            assert_eq!(matcher.fed_bytes, width + 8);
            assert_eq!(matcher.scan(b"x"), None);
            assert_eq!(matcher.matched, 0);
        }
    }
}

#[test]
fn prepared_after_a_complete_match_normalizes_before_indexing() {
    let mut matcher = Matcher::new("aba", false);
    assert_eq!(matcher.scan(b"aba"), Some(3));
    assert!(matcher.failure.is_none());
    matcher.prepare_failure();
    assert_eq!(matcher.scan(b"ba"), Some(2));
    assert_eq!(matcher.fed_bytes, 5);
}

#[test]
fn deferred_matching_remains_connected_to_exact_rope_search() {
    fn rope(left: JsString, right: JsString) -> JsString {
        let shape = left.joined_shape(&right);
        JsString::joined(left, right, shape)
    }
    for word in ["ababa", "aaaaab", "\u{e9}\u{65e5}\u{1f600}"] {
        let spelling = format!("x{word}x{word}x");
        let mut value = JsString::from("");
        for scalar in spelling.chars() {
            value = rope(value, JsString::from(scalar.to_string()));
        }
        let needle = JsString::from(word);
        assert_eq!(value.utf16_index_of(&needle, 0), Some(1));
        assert_eq!(value.utf16_last_index_of(&needle, usize::MAX), Some(word.encode_utf16().count() + 2));
        let Text::Concat(node) = &value.utf8 else { panic!("expected rope") };
        assert!(node.joined.get().is_none());
    }
}
