//! Constant-work UTF-16 boundaries for three-byte BMP runs.
//!
//! A well-formed UTF-8 scalar occupies at most three bytes per UTF-16 unit.
//! Equality is possible only for a three-byte BMP scalar. Cached total lengths
//! therefore prove a fixed-width string without inspecting its contents. A
//! bounded fringe proof also handles ASCII punctuation and astral characters
//! surrounding an otherwise fixed-width run. No string-sized index or cache
//! is allocated, so retained-memory accounting and the value layout are unchanged.

const FRINGE_BYTES: usize = 32;
const MIN_MIDDLE_DISTANCE: usize = 256;

/// Return a byte boundary only when cached lengths prove its position.
/// The caller supplies the exact UTF-16 length and an in-range offset.
#[inline]
pub(super) fn three_byte_boundary(text: &str, length: usize, position: usize) -> Option<usize> {
    debug_assert!(position <= length);
    let maximum = length.checked_mul(3)?;
    let deficit = maximum.checked_sub(text.len())?;
    if deficit == 0 {
        return Some(position * 3);
    }
    if position < MIN_MIDDLE_DISTANCE
        || length - position < MIN_MIDDLE_DISTANCE
        // Each fringe byte accounts for at most two missing bytes (ASCII).
        || deficit > 4 * FRINGE_BYTES
    {
        return None;
    }

    let mut prefix_end = FRINGE_BYTES;
    while !text.is_char_boundary(prefix_end) {
        prefix_end -= 1;
    }
    let mut suffix_start = text.len() - FRINGE_BYTES;
    while !text.is_char_boundary(suffix_start) {
        suffix_start += 1;
    }
    // Round inward: a scalar crossing a fringe is part of the uninspected
    // middle and cannot contribute to the fringe's proof. Every term below
    // is nonnegative, so deficits from different scalars cannot cancel.
    let prefix_units = text[..prefix_end].encode_utf16().count();
    let suffix_units = text[suffix_start..].encode_utf16().count();
    let prefix_deficit = 3 * prefix_units - prefix_end;
    let suffix_deficit = 3 * suffix_units - (text.len() - suffix_start);
    if prefix_deficit + suffix_deficit != deficit {
        return None;
    }
    // position is strictly beyond either bounded fringe. The complete total
    // deficit is in those fringes, proving every middle scalar is three-byte
    // BMP. The checked total multiplication above also bounds this product.
    Some(position * 3 - prefix_deficit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_string::JsString;

    fn assert_boundary(text: &str, position: usize, byte: usize) {
        assert!(text.is_char_boundary(byte));
        assert_eq!(text[..byte].encode_utf16().count(), position);
        assert_eq!(
            super::super::utf16_boundary(text, text.encode_utf16().count(), position),
            (byte, false)
        );
    }

    #[test]
    fn dense_bmp_runs_have_direct_boundaries_at_every_offset() {
        for text in [
            "\u{800}\u{20ac}\u{65e5}\u{d7ff}\u{e000}\u{ffff}".repeat(1024),
            "\u{65e5}".repeat(131072),
        ] {
            let length = text.encode_utf16().count();
            let string = JsString::from(text.as_str());
            for position in 0..=length {
                assert_eq!(
                    three_byte_boundary(&text, length, position),
                    Some(position * 3)
                );
            }
            for position in [0, 1, 255, 256, length / 2, length - 1, length] {
                assert_boundary(&text, position, position * 3);
                let expected = text.encode_utf16().nth(position);
                assert_eq!(string.code_unit_at(position), expected);
                assert_eq!(string.code_point_at(position), expected.map(u32::from));
            }
            for start in [1, 255, 256, length / 2, length - 8] {
                assert_eq!(
                    string.utf16_slice(start, start + 7).as_str(),
                    Some(&text[start * 3..(start + 7) * 3])
                );
            }
        }
    }

    #[test]
    fn bounded_mixed_fringes_leave_the_middle_fixed_width() {
        let fringes = [
            ("", "!"),
            ("ascii:", ":end"),
            ("\u{e9}\u{1f600}", "\u{10ffff}!"),
            ("\u{800}\u{d7ff}", "\u{e000}\u{ffff}"),
        ];
        for width in [1024, 8192, 131072] {
            for (prefix, suffix) in fringes {
                let text = format!("{prefix}{}{suffix}", "\u{65e5}".repeat(width));
                let length = text.encode_utf16().count();
                let prefix_units = prefix.encode_utf16().count();
                let string = JsString::from(text.as_str());
                for position in [256, length / 2, length - 256] {
                    let byte = prefix.len() + (position - prefix_units) * 3;
                    assert_eq!(three_byte_boundary(&text, length, position), Some(byte));
                    assert_boundary(&text, position, byte);
                    assert_eq!(string.code_unit_at(position), Some(0x65e5));
                    assert_eq!(string.code_point_at(position), Some(0x65e5));
                    assert_eq!(
                        string.utf16_slice(position, position + 7).as_str(),
                        Some("日日日日日日日")
                    );
                }
            }
        }
    }

    #[test]
    fn an_interior_non_three_byte_scalar_cannot_pass_the_proof() {
        for scalar in [
            'a', '\u{7f}', '\u{80}', '\u{7ff}', '\u{10000}', '\u{10ffff}',
        ] {
            let text = format!(
                "a{}{scalar}{}!",
                "\u{65e5}".repeat(1024),
                "\u{20ac}".repeat(1024)
            );
            let units: Vec<u16> = text.encode_utf16().collect();
            let string = JsString::from(text.as_str());
            for position in [256, 1024, 1025, 1026, 1027, units.len() - 256] {
                assert_eq!(three_byte_boundary(&text, units.len(), position), None);
                assert_eq!(string.code_unit_at(position), Some(units[position]));
                for width in [1, 2, 7] {
                    assert_eq!(
                        string.utf16_slice(position, position + width).code_units_vec(),
                        units[position..position + width]
                    );
                }
            }
        }
    }

    #[test]
    fn a_split_fringe_scalar_cannot_supply_the_missing_deficit() {
        for scalar in ['\u{e9}', '\u{1f600}'] {
            for pad in FRINGE_BYTES - scalar.len_utf8() + 1..FRINGE_BYTES {
                let padding = "x".repeat(pad);
                let middle = "\u{65e5}".repeat(2048);
                for text in [
                    format!("{padding}{scalar}{middle}"),
                    format!("{middle}{scalar}{padding}"),
                ] {
                    let length = text.encode_utf16().count();
                    let position = length / 2;
                    assert_eq!(three_byte_boundary(&text, length, position), None);
                    let (byte, second) = super::super::utf16_boundary(&text, length, position);
                    assert!(!second);
                    assert_boundary(&text, position, byte);
                }
            }
        }
    }

    #[test]
    fn equal_two_byte_ratio_is_not_a_fixed_width_proof() {
        // Both strings have two UTF-8 bytes per UTF-16 unit on average, but
        // neither licenses a byte = 2 * position shortcut.
        for text in ["a\u{65e5}".repeat(512), "\u{e9}\u{1f600}".repeat(512)] {
            let length = text.encode_utf16().count();
            assert_eq!(text.len(), length * 2);
            for position in [256, length / 2, length - 256] {
                assert_eq!(three_byte_boundary(&text, length, position), None);
            }
        }
    }

    #[test]
    fn proof_rejects_an_overflowing_cached_length() {
        assert_eq!(three_byte_boundary("", usize::MAX, 0), None);
    }
}
