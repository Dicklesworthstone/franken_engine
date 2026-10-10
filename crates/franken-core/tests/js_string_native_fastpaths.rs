#![forbid(unsafe_code)]

use frankenengine_core::js_string::JsString;
use proptest::prelude::*;

fn reference_search(haystack: &[u16], needle: &[u16], from: usize, last: bool) -> Option<usize> {
    let from = from.min(haystack.len());
    if needle.is_empty() {
        return Some(from);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    let mut matches = (0..=haystack.len() - needle.len())
        .filter(|&index| &haystack[index..index + needle.len()] == needle);
    if last {
        matches.rfind(|&index| index <= from)
    } else {
        matches.find(|&index| index >= from)
    }
}

fn reference_elements(units: &[u16]) -> Vec<Vec<u16>> {
    let mut result = Vec::new();
    let mut at = 0;
    while at < units.len() {
        let paired = (0xd800..=0xdbff).contains(&units[at])
            && units
                .get(at + 1)
                .is_some_and(|unit| (0xdc00..=0xdfff).contains(unit));
        let end = at + if paired { 2 } else { 1 };
        result.push(units[at..end].to_vec());
        at = end;
    }
    result
}

fn assert_search(haystack: &[u16], needle: &[u16], from: usize) {
    let value = JsString::from_code_units(haystack);
    let other = JsString::from_code_units(needle);
    assert_eq!(
        value.utf16_index_of(&other, from),
        reference_search(haystack, needle, from, false),
        "indexOf: {haystack:?}, {needle:?}, {from}"
    );
    assert_eq!(
        value.utf16_last_index_of(&other, from),
        reference_search(haystack, needle, from, true),
        "lastIndexOf: {haystack:?}, {needle:?}, {from}"
    );
}

#[test]
fn ascii_search_boundaries_overlap_nul_and_non_ascii_rejection() {
    let haystacks = ["", "aaaaa", "abababa", "abc\0abc\x7f", "abc", "needle"];
    let needles = [
        "",
        "a",
        "aaa",
        "aba",
        "\0",
        "c\x7f",
        "needle",
        "é",
        "😀",
        "longer-than-haystack",
    ];
    for haystack in haystacks {
        let value = JsString::from(haystack);
        let units: Vec<u16> = haystack.encode_utf16().collect();
        for needle in needles {
            let needle_units: Vec<u16> = needle.encode_utf16().collect();
            for from in (0..=units.len() + 2).chain([usize::MAX]) {
                assert_search(&units, &needle_units, from);
            }
        }
        for unit in [0xd800, 0xdbff, 0xdc00, 0xdfff] {
            let needle = JsString::from_code_units(&[unit]);
            assert_eq!(value.utf16_index_of(&needle, 0), None);
            assert_eq!(value.utf16_last_index_of(&needle, usize::MAX), None);
        }
    }
}

#[test]
fn unicode_byte_windows_match_all_short_scalar_strings_and_offsets() {
    fn corpus(max_len: usize) -> Vec<Vec<u16>> {
        let mut all = vec![Vec::new()];
        let mut level = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &level {
                for ch in ['\0', 'a', 'é', '中', '😀', '\u{10ffff}'] {
                    let mut value = prefix.clone();
                    let mut buffer = [0_u16; 2];
                    value.extend_from_slice(ch.encode_utf16(&mut buffer));
                    next.push(value);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    let needles = corpus(2);
    for haystack in corpus(3) {
        for needle in &needles {
            for from in (0..=haystack.len() + 1).chain([usize::MAX]) {
                assert_search(&haystack, needle, from);
            }
        }
    }
}

#[test]
fn mixed_width_reverse_search_keeps_matches_crossing_the_start_bound() {
    for haystack in ["é😀é😀", "a😀😀b", "中aé中aé", "😀a😀a😀", "é中😀"] {
        let units: Vec<u16> = haystack.encode_utf16().collect();
        // Every code-unit substring: includes lone-surrogate needles that
        // must retain the exact-unit fallback, even in a well-formed haystack.
        for start in 0..=units.len() {
            for end in start..=units.len() {
                for from in (0..=units.len() + 1).chain([usize::MAX]) {
                    assert_search(&units, &units[start..end], from);
                }
            }
        }
    }
}

#[test]
fn empty_concatenation_reuses_existing_backing() {
    for units in [vec![0x61, 0x62], vec![0xd83d, 0xde00], vec![0xd800, 0x61]] {
        let value = JsString::from_code_units(&units);
        let left = JsString::empty().concat(&value);
        let right = value.concat(&JsString::empty());
        assert_eq!(left, value);
        assert_eq!(right, value);
        assert!(std::ptr::eq(
            left.as_utf8_projection(),
            value.as_utf8_projection()
        ));
        assert!(std::ptr::eq(
            right.as_utf8_projection(),
            value.as_utf8_projection()
        ));
    }
}

#[test]
fn streamed_elements_preserve_surrogate_boundaries() {
    for units in [
        vec![],
        vec![0, 0x7f],
        vec![0x61, 0xd83d, 0xde00, 0x62],
        vec![0xd800, 0xd83d, 0xde00, 0xdc00],
        vec![0x80, 0xe000, 0xffff],
    ] {
        let value = JsString::from_code_units(&units);
        let elements = value.code_point_elements();
        let actual: Vec<Vec<u16>> = elements.iter().map(JsString::code_units_vec).collect();
        assert_eq!(actual, reference_elements(&units));
        assert_eq!(actual.into_iter().flatten().collect::<Vec<_>>(), units);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn ascii_search_and_comparison_match_exact_units(
        haystack in prop::collection::vec(0_u16..128, 0..128),
        needle in prop::collection::vec(0_u16..128, 0..16),
        from in prop_oneof![0_usize..160, Just(usize::MAX)],
    ) {
        assert_search(&haystack, &needle, from);
        let value = JsString::from_code_units(&haystack);
        let other = JsString::from_code_units(&needle);
        prop_assert_eq!(value.utf16_cmp(&other), haystack.cmp(&needle));
    }

    #[test]
    fn unicode_search_and_streamed_elements_match_exact_units(
        haystack in prop::collection::vec(any::<u16>(), 0..64),
        needle in prop::collection::vec(any::<u16>(), 0..8),
        from in prop_oneof![0_usize..80, Just(usize::MAX)],
    ) {
        assert_search(&haystack, &needle, from);
        let value = JsString::from_code_units(&haystack);
        let other = JsString::from_code_units(&needle);
        prop_assert_eq!(value.utf16_cmp(&other), haystack.cmp(&needle));
        let elements: Vec<Vec<u16>> = value.code_point_elements()
            .iter().map(JsString::code_units_vec).collect();
        prop_assert_eq!(&elements, &reference_elements(&haystack));
        prop_assert_eq!(elements.into_iter().flatten().collect::<Vec<_>>(), haystack);
    }

    #[test]
    fn arbitrary_unicode_substrings_retain_positive_matches(
        chars in prop::collection::vec(any::<char>(), 0..64),
        a in 0_usize..160,
        b in 0_usize..160,
        from in prop_oneof![0_usize..160, Just(usize::MAX)],
    ) {
        let text: String = chars.into_iter().collect();
        let units: Vec<u16> = text.encode_utf16().collect();
        let a = a % (units.len() + 1);
        let b = b % (units.len() + 1);
        // Splitting a pair exercises the fallback; whole pairs exercise the
        // allocation-free UTF-8 path with actual, rather than mostly absent, hits.
        let needle = &units[a.min(b)..a.max(b)];
        assert_search(&units, needle, from);
        assert_search(&units, needle, a.min(b));
    }
}
