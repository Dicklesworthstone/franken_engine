//! Allocation-free search coordinates for published, well-formed strings.
//!
//! Byte search itself is delegated to str. Cached total lengths and the
//! existing indexed-access boundary proof locate the requested UTF-16 start;
//! the returned match is counted from its closest known coordinate, excluding
//! the needle's already-known length. Neither input gains an index or cache.
//! Unpublished ropes and exact-only strings keep their existing search paths.

use super::access;

/// The public caller already handled empty/oversized needles and clamped from.
pub(super) fn index_of(
    text: &str,
    length: usize,
    pattern: &str,
    pattern_units: usize,
    from: usize,
) -> Option<usize> {
    debug_assert!(!pattern.is_empty() && pattern_units <= length - from);
    let (byte_start, unit_start) = search_boundary(text, length, from, true);
    let found = byte_start + text[byte_start..].find(pattern)?;
    Some(match_index(
        text,
        length,
        pattern.len(),
        pattern_units,
        found,
        (byte_start, unit_start),
        |span| span.encode_utf16().count(),
    ))
}

/// last_start is the largest permitted starting position, not a match end.
pub(super) fn last_index_of(
    text: &str,
    length: usize,
    pattern: &str,
    pattern_units: usize,
    last_start: usize,
) -> Option<usize> {
    debug_assert!(!pattern.is_empty() && pattern_units <= length);
    debug_assert!(last_start <= length - pattern_units);
    let (end, anchor) = if last_start == length - pattern_units {
        // Every fitting start is allowed. No boundary search is necessary.
        (text.len(), (0, 0))
    } else {
        let (byte, unit) = search_boundary(text, length, last_start, false);
        // Include a complete pattern starting at the permitted scalar. Byte
        // equality fixes the match width, so a later start cannot fit in this
        // window. Rounding its end down excludes no complete UTF-8 match.
        let mut end = byte + pattern.len().min(text.len() - byte);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        (end, (byte, unit))
    };
    let found = text[..end].rfind(pattern)?;
    Some(match_index(
        text,
        length,
        pattern.len(),
        pattern_units,
        found,
        anchor,
        |span| span.encode_utf16().count(),
    ))
}

/// A split pair rounds UP for indexOf, DOWN for lastIndexOf. The canonical
/// boundary routine already proves its byte start; an astral scalar always
/// occupies four UTF-8 bytes and two UTF-16 units. No second prefix scan.
fn search_boundary(
    text: &str,
    length: usize,
    position: usize,
    round_up: bool,
) -> (usize, usize) {
    let (byte, split_pair) = access::utf16_search_boundary(text, length, position);
    if !split_pair {
        (byte, position)
    } else if round_up {
        (byte + 4, position + 1)
    } else {
        (byte, position - 1)
    }
}

/// Convert a proved byte match using the shortest of three spans: the prefix
/// before it, the distance from the search boundary, or the suffix AFTER the
/// complete needle. Counting a needle again is unnecessary in either direction.
///
/// count is a statically specialized seam for structural regression checks;
/// production uses the ordinary UTF-16 counter, not a callback into guest code.
fn match_index(
    text: &str,
    length: usize,
    pattern_bytes: usize,
    pattern_units: usize,
    found: usize,
    (anchor_byte, anchor_unit): (usize, usize),
    count: impl FnOnce(&str) -> usize,
) -> usize {
    // In well-formed UTF-8 a scalar contributes at most three bytes per
    // UTF-16 unit, with equality only for a three-byte BMP scalar. Equality
    // of the cached totals therefore proves every boundary without scanning
    // either side of the match. An average of two bytes would NOT be a proof:
    // ASCII/three-byte mixtures and astral scalars can have that same ratio.
    if length.checked_mul(3) == Some(text.len()) {
        debug_assert_eq!(found % 3, 0);
        return found / 3;
    }
    let end = found + pattern_bytes;
    let suffix = text.len() - end;
    let distance = found.abs_diff(anchor_byte);
    if suffix < found && suffix < distance {
        length - pattern_units - count(&text[end..])
    } else if found < distance {
        count(&text[..found])
    } else if found >= anchor_byte {
        anchor_unit + count(&text[anchor_byte..found])
    } else {
        anchor_unit - count(&text[found..anchor_byte])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_rounding_matches_each_exact_utf16_position() {
        for text in ["", "ascii", "\0é中😀\u{10ffff}!", "😀😀a😀", "a中a中"] {
            let length = text.encode_utf16().count();
            for position in 0..=length {
                assert_eq!(
                    access::utf16_boundary(text, length, position),
                    access::utf16_search_boundary(text, length, position)
                );
                let boundaries: Vec<_> = text.char_indices().map(|(byte, _)| {
                    (byte, text[..byte].encode_utf16().count())
                }).chain([(text.len(), length)]).collect();
                let down = boundaries.iter().rfind(|(_, unit)| *unit <= position).copied().unwrap();
                let up = boundaries.iter().find(|(_, unit)| *unit >= position).copied().unwrap();
                assert_eq!(search_boundary(text, length, position, false), down);
                assert_eq!(search_boundary(text, length, position, true), up);
            }
        }
    }

    #[test]
    fn every_match_and_anchor_counts_only_the_shortest_known_span() {
        for text in ["aé中😀\u{10ffff}é中a", "😀😀😀", "éaéaé"] {
            let length = text.encode_utf16().count();
            let boundaries: Vec<_> = text.char_indices().map(|(byte, _)| byte)
                .chain([text.len()]).collect();
            for (at, &found) in boundaries.iter().enumerate().take(boundaries.len() - 1) {
                for &end in &boundaries[at + 1..] {
                    let pattern_units = text[found..end].encode_utf16().count();
                    for &anchor_byte in &boundaries {
                        let anchor_unit = text[..anchor_byte].encode_utf16().count();
                        let mut counted = None;
                        let result = match_index(text, length, end - found, pattern_units,
                            found, (anchor_byte, anchor_unit), |span| {
                                counted = Some(span.len());
                                span.encode_utf16().count()
                            });
                        assert_eq!(result, text[..found].encode_utf16().count());
                        assert_eq!(counted, Some(found.min(found.abs_diff(anchor_byte))
                            .min(text.len() - end)));
                    }
                }
            }
        }
    }

    #[test]
    fn endpoint_matches_do_not_recount_a_long_prefix_or_long_needle() {
        for text in ["é中😀".repeat(32768), "中".repeat(131072)] {
            let length = text.encode_utf16().count();
            for (found, end) in [(0, text.len()), (text.len() - 3, text.len())] {
                // The mixed fixture ends in an astral scalar: choose its start.
                let mut found = found;
                while !text.is_char_boundary(found) { found -= 1; }
                let units = text[found..end].encode_utf16().count();
                let mut bytes = 0;
                let result = match_index(&text, length, end - found, units,
                    found, (0, 0), |span| {
                        bytes += span.len();
                        span.encode_utf16().count()
                    });
                assert_eq!(result, length - units);
                assert_eq!(bytes, 0);
            }
        }
    }

    #[test]
    fn fixed_width_bmp_matches_never_decode_a_coordinate_span() {
        for repeats in [1, 7, 257, 8192] {
            let text = "\u{800}\u{20ac}\u{65e5}\u{d7ff}\u{e000}\u{ffff}".repeat(repeats);
            let length = text.encode_utf16().count();
            assert_eq!(text.len(), length * 3);
            for position in [0, 1, length / 2, length - 1] {
                for width in [1, 3, length - position] {
                    let width = width.min(length - position);
                    for anchor in [0, length / 2, length] {
                        assert_eq!(
                            match_index(&text, length, width * 3, width,
                                position * 3, (anchor * 3, anchor), |_| {
                                    panic!("cached three-byte width must avoid decoding")
                                }),
                            position
                        );
                    }
                }
            }
            for from in [0, 1, length / 2, length - 6] {
                let pattern = "\u{65e5}\u{d7ff}";
                let expected_first = (from..=length - 2).find(|&index| index % 6 == 2);
                let expected_last = (0..=from.min(length - 2)).rfind(|&index| index % 6 == 2);
                assert_eq!(index_of(&text, length, pattern, 2, from), expected_first);
                assert_eq!(last_index_of(&text, length, pattern, 2,
                    from.min(length - 2)), expected_last);
            }
        }
    }

    #[test]
    fn mixed_width_match_positions_cannot_use_an_average_byte_ratio() {
        for text in [
            "a中".repeat(513), "é😀".repeat(513),
            format!("{}a{}", "中".repeat(513), "中".repeat(513)),
            format!("{}😀{}", "中".repeat(513), "中".repeat(513)),
        ] {
            let length = text.encode_utf16().count();
            assert_ne!(length.checked_mul(3), Some(text.len()));
            for (found, scalar) in text.char_indices() {
                let expected = text[..found].encode_utf16().count();
                assert_eq!(match_index(&text, length, scalar.len_utf8(),
                    scalar.len_utf16(), found, (0, 0), |span| {
                        span.encode_utf16().count()
                    }), expected);
            }
        }
    }

    #[test]
    fn searches_preserve_byte_windows_and_split_pair_offsets() {
        for text in ["é😀é😀", "中aé中aé", "😀a😀a😀", "é中😀", "aaéaaaé"] {
            let length = text.encode_utf16().count();
            let units: Vec<_> = text.encode_utf16().collect();
            let bounds: Vec<_> = text.char_indices().map(|(byte, _)| byte)
                .chain([text.len()]).collect();
            for (at, &start) in bounds.iter().enumerate().take(bounds.len() - 1) {
                for &end in &bounds[at + 1..] {
                    let needle = &text[start..end];
                    let needle_units: Vec<_> = needle.encode_utf16().collect();
                    for from in 0..=length - needle_units.len() {
                        let first = units.windows(needle_units.len()).enumerate()
                            .find(|(i, candidate)| *i >= from && *candidate == needle_units.as_slice())
                            .map(|(i, _)| i);
                        let last = units.windows(needle_units.len()).enumerate()
                            .rfind(|(i, candidate)| *i <= from && *candidate == needle_units.as_slice())
                            .map(|(i, _)| i);
                        assert_eq!(index_of(text, length, needle, needle_units.len(), from), first);
                        assert_eq!(
                            last_index_of(text, length, needle, needle_units.len(), from),
                            last
                        );
                    }
                }
            }
        }
    }
}
