//! Indexed UTF-16 access without eagerly materializing concatenations.
//!
//! Keep the flat readers and rope traversal together: neither the engine
//! re-export nor the extracted core may fork these string semantics.

use std::sync::Arc;

use super::{JsString, Shape, Text, is_high_surrogate, is_low_surrogate};

/// Bound pointer chasing before settling a deeply skewed rope. Without a
/// limit, a forward scan of an append chain could walk the whole chain for
/// every character. The fallback joins the original root once, so subsequent
/// reads reuse that buffer. Reading a recently appended/prepended leaf does
/// not reach the fallback, regardless of the accumulated string's length.
const MAX_INDEX_DESCENT: usize = 32;

impl JsString {
    /// Read at an in-range UTF-16 offset in a leaf or an already joined node.
    /// Concatenation children are well-formed, so a surrogate pair cannot
    /// straddle their boundary. CodePointAt can therefore read both halves
    /// from the selected piece without traversing the rope twice.
    fn with_indexed_piece<R>(
        &self,
        unit_index: usize,
        read: impl FnOnce(&JsString, usize) -> R,
    ) -> R {
        let Text::Concat(root) = &self.utf8 else {
            return read(self, unit_index);
        };
        if root.joined.get().is_some() {
            return read(self, unit_index);
        }
        let mut piece = self.clone();
        let mut index = unit_index;
        for _ in 0..MAX_INDEX_DESCENT {
            let Text::Concat(node) = &piece.utf8 else {
                return read(&piece, index);
            };
            if node.joined.get().is_some() {
                return read(&piece, index);
            }
            let Some([left, right]) = node.parts() else {
                // A concurrent join may publish its buffer and release the
                // parts after our first check. The flat reader sees that
                // published buffer, never an absent child or a lossy view.
                return read(&piece, index);
            };
            let split = left.utf16_len();
            piece = if index < split {
                left
            } else {
                index -= split;
                right
            };
        }
        if matches!(&piece.utf8, Text::Flat(_)) {
            read(&piece, index)
        } else {
            // Join the root, not just a deep descendant: later sequential
            // reads must not repeat MAX_INDEX_DESCENT pointer traversals.
            read(self, unit_index)
        }
    }

    /// The UTF-16 code unit at `unit_index`, or `None` out of range. Rope
    /// reads descend by cached UTF-16 lengths instead of copying unrelated
    /// text. ASCII leaves retain direct byte access (bd-9vouw.403).
    pub fn code_unit_at(&self, unit_index: usize) -> Option<u16> {
        if unit_index >= self.utf16_len() {
            return None;
        }
        self.with_indexed_piece(unit_index, |piece, index| match &piece.shape {
            Shape::Exact(units) => units.get(index).copied(),
            Shape::WellFormed { .. } => {
                let bytes = piece.utf8.as_bytes();
                if piece.is_ascii_text() {
                    return bytes.get(index).map(|byte| u16::from(*byte));
                }
                match bytes.get(..=index) {
                    Some(prefix) if prefix.is_ascii() => Some(u16::from(bytes[index])),
                    _ => piece.utf8.encode_utf16().nth(index),
                }
            }
        })
    }

    /// ES2020 `CodePointAt`: a UTF-16 index, combining an adjacent high/low
    /// pair, preserving either lone half, and returning `None` out of range.
    /// Like code_unit_at, this does not flatten a rope for a nearby leaf.
    pub fn code_point_at(&self, unit_index: usize) -> Option<u32> {
        if unit_index >= self.utf16_len() {
            return None;
        }
        self.with_indexed_piece(unit_index, |piece, index| {
            if piece.is_ascii_text() {
                return piece
                    .utf8
                    .as_bytes()
                    .get(index)
                    .map(|byte| u32::from(*byte));
            }
            if piece.is_well_formed()
                && let Some(prefix) = piece.utf8.as_bytes().get(..=index)
                && prefix.is_ascii()
            {
                return Some(u32::from(prefix[index]));
            }
            let mut units = piece.encode_utf16().skip(index);
            let first = units.next()?;
            if is_high_surrogate(first)
                && let Some(second) = units.next()
                && is_low_surrogate(second)
            {
                let high = u32::from(first) - 0xD800;
                let low = u32::from(second) - 0xDC00;
                return Some(0x10000 + (high << 10) + low);
            }
            Some(u32::from(first))
        })
    }

    /// The code units from `start` to `end` (clamped UTF-16 offsets). A
    /// boundary inside a surrogate pair preserves the lone half.
    pub fn utf16_slice(&self, start: usize, end: usize) -> JsString {
        let end = end.min(self.utf16_len());
        let start = start.min(end);
        match &self.shape {
            Shape::WellFormed { .. } if self.is_ascii_text() => Self {
                utf8: Text::Flat(Arc::from(&self.utf8[start..end])),
                shape: Shape::WellFormed {
                    utf16_len: end - start,
                },
            },
            Shape::WellFormed { .. } => {
                let units: Vec<u16> = self
                    .utf8
                    .encode_utf16()
                    .skip(start)
                    .take(end - start)
                    .collect();
                Self::from_code_units(&units)
            }
            Shape::Exact(units) => Self::from_code_units(&units[start..end]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_string::CONCAT_COPY_MAX_BYTES;

    fn assert_unjoined(string: &JsString) {
        let Text::Concat(node) = &string.utf8 else {
            panic!("fixture must be a concatenation");
        };
        assert!(node.joined.get().is_none(), "indexed read flattened the rope");
        assert!(node.parts().is_some());
    }

    fn reference_point(units: &[u16], index: usize) -> Option<u32> {
        let first = *units.get(index)?;
        match units.get(index + 1) {
            Some(&second) if is_high_surrogate(first) && is_low_surrogate(second) => {
                Some(0x10000 + ((u32::from(first) - 0xD800) << 10) + u32::from(second) - 0xDC00)
            }
            _ => Some(u32::from(first)),
        }
    }

    #[test]
    fn every_rope_index_matches_units_without_materializing() {
        let texts = [
            "a".repeat(1100),
            "\u{e9}\u{1f600}z".repeat(200),
            "\u{1f600}\u{65e5}".repeat(200),
            "tail".repeat(300),
        ];
        let pieces = texts.each_ref().map(|text| JsString::from(text.as_str()));
        let left = pieces[0].concat(&pieces[1]);
        let right = pieces[2].concat(&pieces[3]);
        let rope = left.concat(&right);
        let units: Vec<u16> = texts.concat().encode_utf16().collect();
        let retained = rope.retained_bytes(24);
        for index in (0..=units.len()).chain(std::iter::once(usize::MAX)) {
            assert_eq!(rope.code_unit_at(index), units.get(index).copied(), "{index}");
            assert_eq!(
                rope.code_point_at(index),
                reference_point(&units, index),
                "{index}"
            );
        }
        for string in [&left, &right, &rope] {
            assert_unjoined(string);
        }
        assert_eq!(rope.retained_bytes(24), retained);
        assert_eq!(rope.as_str(), Some(texts.concat().as_str()));
        assert_eq!(rope.retained_bytes(24), retained);
        for index in 0..=units.len() {
            assert_eq!(rope.code_unit_at(index), units.get(index).copied());
            assert_eq!(rope.code_point_at(index), reference_point(&units, index));
        }
    }

    #[test]
    fn append_and_prepend_then_read_keep_the_accumulated_text_lazy() {
        let pieces = ["abc", "x\u{e9}", "a\u{1f600}b"].map(JsString::from);
        for prepend in [false, true] {
            let mut rope = JsString::from("prefix".repeat(300));
            for round in 0..2048 {
                let piece = &pieces[round % pieces.len()];
                let units = piece.code_units_vec();
                rope = if prepend {
                    piece.concat(&rope)
                } else {
                    rope.concat(piece)
                };
                let start = if prepend {
                    0
                } else {
                    rope.utf16_len() - units.len()
                };
                for index in 0..units.len() {
                    assert_eq!(rope.code_unit_at(start + index), Some(units[index]));
                    assert_eq!(
                        rope.code_point_at(start + index),
                        reference_point(&units, index)
                    );
                }
                assert_eq!(rope.code_unit_at(usize::MAX), None);
                assert_eq!(rope.code_point_at(rope.utf16_len()), None);
                assert_unjoined(&rope);
            }
        }
    }

    #[test]
    fn out_of_range_reads_do_not_join_or_overflow() {
        for text in ["a", "\u{e9}", "\u{1f600}"] {
            let piece = JsString::from(text.repeat(1100));
            let rope = piece.concat(&piece);
            for index in [rope.utf16_len(), rope.utf16_len() + 1, usize::MAX] {
                assert_eq!(rope.code_unit_at(index), None);
                assert_eq!(rope.code_point_at(index), None);
                assert_unjoined(&rope);
            }
        }
    }

    #[test]
    fn deep_index_descent_settles_the_root_once_for_sequential_reads() {
        let piece = JsString::from("x".repeat(CONCAT_COPY_MAX_BYTES + 1));
        for prepend in [false, true] {
            for point in [false, true] {
                let mut rope = piece.clone();
                for _ in 0..MAX_INDEX_DESCENT + 16 {
                    rope = if prepend {
                        piece.concat(&rope)
                    } else {
                        rope.concat(&piece)
                    };
                }
                let index = if prepend {
                    rope.utf16_len() - 1
                } else {
                    0
                };
                assert_unjoined(&rope);
                if point {
                    assert_eq!(rope.code_point_at(index), Some(u32::from(b'x')));
                } else {
                    assert_eq!(rope.code_unit_at(index), Some(u16::from(b'x')));
                }
                let Text::Concat(node) = &rope.utf8 else {
                    unreachable!()
                };
                assert!(node.joined.get().is_some());
                assert!(node.parts().is_none());
                assert_eq!(
                    rope.code_unit_at(rope.utf16_len() - 1),
                    Some(u16::from(b'x'))
                );
            }
        }
    }

    #[test]
    fn indexed_reads_preserve_lone_surrogates_and_healed_pairs() {
        let alphabet = [0x61, 0xD800, 0xDC00, 0xDFFF, 0xE000];
        for a in alphabet {
            for b in alphabet {
                for c in alphabet {
                    let units = [a, b, c];
                    let string = JsString::from_code_units(&units);
                    for index in (0..=units.len()).chain(std::iter::once(usize::MAX)) {
                        assert_eq!(string.code_unit_at(index), units.get(index).copied());
                        assert_eq!(string.code_point_at(index), reference_point(&units, index));
                    }
                }
            }
        }
    }

    #[test]
    fn join_retains_a_child_published_after_the_initial_cache_check() {
        let left = "a".repeat(1100);
        let right = "\u{1f600}".repeat(300);
        let child = JsString::from(left.as_str()).concat(&JsString::from(right.as_str()));
        let Text::Concat(node) = &child.utf8 else {
            unreachable!()
        };
        // Deterministically schedule the race in Concat::join: its first
        // cache check misses, then another reader publishes and drops parts.
        assert!(node.joined.get().is_none());
        let expected = format!("{left}{right}");
        assert_eq!(node.joined_text(), expected);
        assert!(node.parts().is_none());
        let mut text = String::from("before:");
        let mut pending = Vec::new();
        node.queue_parts_or_joined(&mut text, &mut pending);
        assert!(pending.is_empty());
        assert_eq!(text, format!("before:{expected}"));
        assert_eq!(child.code_point_at(1100), Some(0x1f600));
    }
}
