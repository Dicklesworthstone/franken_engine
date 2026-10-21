//! Shared public string searches: cached boundaries and nearest match offsets.
#![forbid(unsafe_code)]

use frankenengine_core::js_string::JsString;

fn reference(haystack: &[u16], needle: &[u16], from: usize, last: bool) -> Option<usize> {
    let from = from.min(haystack.len());
    if needle.is_empty() {
        return Some(from);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    let mut hits = haystack.windows(needle.len()).enumerate()
        .filter(|(_, candidate)| *candidate == needle);
    if last {
        hits.rfind(|(index, _)| *index <= from).map(|(index, _)| index)
    } else {
        hits.find(|(index, _)| *index >= from).map(|(index, _)| index)
    }
}

fn check(text: &JsString, needle: &JsString, positions: impl IntoIterator<Item = usize>) {
    let units = text.code_units_vec();
    let pattern = needle.code_units_vec();
    for from in positions {
        assert_eq!(text.utf16_index_of(needle, from), reference(&units, &pattern, from, false),
            "forward from={from}, lengths={}/{}", units.len(), pattern.len());
        assert_eq!(text.utf16_last_index_of(needle, from), reference(&units, &pattern, from, true),
            "reverse from={from}, lengths={}/{}", units.len(), pattern.len());
    }
}

#[test]
fn every_offset_preserves_pairs_overlaps_empty_patterns_and_oversized_bounds() {
    for input in ["", "ascii\0ascii", "aé中😀\u{10ffff}é😀", "😀😀a😀", "éaéaé"] {
        let text = JsString::from(input);
        let units = text.code_units_vec();
        for start in 0..=units.len() {
            for end in start..=units.len() {
                check(&text, &JsString::from_code_units(&units[start..end]),
                    (0..=units.len() + 1).chain([usize::MAX]));
            }
        }
        check(&text, &JsString::from("absent-and-longer-than-the-input"),
            [0, units.len(), usize::MAX]);
    }
}

#[test]
fn long_flat_unicode_searches_keep_tail_and_fringe_coordinates_exact() {
    for input in [
        format!("{}ENDé😀", "é中😀a".repeat(8192)),
        format!("é😀{}END", "ascii".repeat(8192)),
        format!("{}END", "中".repeat(32768)),
        format!("!{}😀", "中".repeat(32768)),
        format!("{}é中{}!", "a".repeat(16382), "a".repeat(16384)),
        format!("{}{}", "a".repeat(20000), "中".repeat(12000)),
        format!("{}{}", "中".repeat(12000), "a".repeat(20000)),
    ] {
        let text = JsString::from(input);
        assert!(text.unjoined_concat_children().is_none());
        let length = text.utf16_len();
        for needle in ["", "END", "é😀", "😀", "中中中", "ascii", "absent"] {
            check(&text, &JsString::from(needle), [0, 1, 255, 256, length / 2,
                length / 2 - 1, length - 257, length - 256, length - 7, length - 2, length - 1,
                length, usize::MAX]);
        }
    }
}

#[test]
fn fixed_width_flat_searches_use_exact_middle_and_end_coordinates() {
    for padding in [0, 1, 256, 4096] {
        let input = format!("{}語{}語{}", "中".repeat(padding),
            "日".repeat(padding), "文".repeat(padding));
        let text = JsString::from(input);
        assert!(text.unjoined_concat_children().is_none());
        assert_eq!(text.len(), 3 * text.utf16_len());
        for needle in ["語", "日", "語日", "日語", "中中", "文文", "", "ない"] {
            check(&text, &JsString::from(needle), [0, padding, padding + 1,
                2 * padding + 1, text.utf16_len(), usize::MAX]);
        }
    }
}

#[test]
fn unjoined_and_published_rope_searches_agree_without_eager_joining() {
    let left = JsString::from(format!("{}é", "中".repeat(2048)));
    let right = JsString::from(format!("😀{}end", "x".repeat(2048)));
    let text = left.concat(&right);
    assert!(text.unjoined_concat_children().is_some());
    let positions = [0, 2047, 2048, 2049, 2050, 2051, text.utf16_len() - 4, usize::MAX];
    for needle in ["é😀", "😀", "xend", "end", "中é"] {
        check(&text, &JsString::from(needle), positions);
    }
    assert!(text.unjoined_concat_children().is_some(), "search must not join the input");
    let _ = text.as_utf8_projection();
    assert!(text.unjoined_concat_children().is_none());
    for needle in ["é😀", "😀", "xend", "end", "中é"] {
        check(&text, &JsString::from(needle), positions);
    }
}

#[test]
fn exact_only_haystacks_and_needles_still_distinguish_lone_surrogates() {
    for units in [
        vec![0xd800, 0x61, 0xd83d, 0xde00, 0xdc00, 0xfffd],
        vec![0xfffd, 0xd800, 0xd800, 0x61, 0xdfff],
        vec![0x4e2d, 0xd83d, 0xde00, 0x4e2d],
    ] {
        let text = JsString::from_code_units(&units);
        for start in 0..=units.len() {
            for end in start..=units.len() {
                check(&text, &JsString::from_code_units(&units[start..end]),
                    (0..=units.len() + 1).chain([usize::MAX]));
            }
        }
    }
}
