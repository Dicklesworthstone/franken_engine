//! Indexed UTF-16 access without eagerly materializing concatenations.
//!
//! Keep the flat readers and rope traversal together: neither the engine
//! re-export nor the extracted core may fork these string semantics.

use std::sync::Arc;

use super::{JsString, Shape, Text, is_high_surrogate, is_low_surrogate};

mod fixed_width;

/// Bound pointer chasing before settling a deeply skewed rope. Without a
/// limit, a forward scan of an append chain could walk the whole chain for
/// every character. The fallback joins the original root once, so subsequent
/// reads reuse that buffer. Reading a recently appended/prepended leaf does
/// not reach the fallback, regardless of the accumulated string's length.
const MAX_INDEX_DESCENT: usize = 32;

/// Inspect at most this many bytes at either end when proving that a long
/// string's interior is ASCII. No index table or per-string cache is needed.
const ASCII_FRINGE_BYTES: usize = 32;

/// Short scans are cheaper than the proof. This also puts an eligible index
/// strictly inside the middle, beyond either inspected fringe.
const ASCII_MIDDLE_MIN_DISTANCE: usize = 256;

/// A direct byte offset when the cached lengths prove the middle is ASCII.
/// Every non-ASCII scalar contributes a strictly positive UTF-8-byte minus
/// UTF-16-unit excess: 1 for two-byte BMP, 2 for three-byte BMP or astral.
/// If the two fringes account for ALL that excess, there cannot be another
/// non-ASCII scalar in the middle. Repeated indexing of `"é" + long_ascii`
/// then does bounded work instead of rescanning a growing prefix each time.
fn ascii_middle_boundary(text: &str, length: usize, position: usize) -> Option<usize> {
    if position < ASCII_MIDDLE_MIN_DISTANCE || length - position < ASCII_MIDDLE_MIN_DISTANCE {
        return None;
    }
    let excess = text.len() - length;
    if excess == 0 {
        return Some(position);
    }
    // Dense Unicode cannot fit in the fringes; do not scan them speculatively.
    if excess > 2 * ASCII_FRINGE_BYTES {
        return None;
    }
    let mut prefix_end = ASCII_FRINGE_BYTES;
    while !text.is_char_boundary(prefix_end) {
        prefix_end -= 1;
    }
    let mut suffix_start = text.len() - ASCII_FRINGE_BYTES;
    while !text.is_char_boundary(suffix_start) {
        suffix_start += 1;
    }
    // Round INWARD so the proof never charges a partial scalar's excess.
    let prefix_excess = prefix_end - text[..prefix_end].encode_utf16().count();
    let suffix_excess = text.len() - suffix_start - text[suffix_start..].encode_utf16().count();
    (prefix_excess + suffix_excess == excess).then_some(position + prefix_excess)
}

/// Locate a UTF-16 boundary in well-formed UTF-8. A true second component
/// means the position is between the halves of the astral scalar beginning
/// at the returned byte. Search from the nearer end; ASCII spans retain a
/// vectorizable byte check rather than decoding each character.
fn utf16_boundary(text: &str, length: usize, position: usize) -> (usize, bool) {
    debug_assert!(position <= length);
    if position == 0 {
        return (0, false);
    }
    let remaining = length - position;
    if remaining == 0 {
        return (text.len(), false);
    }
    if let Some(byte) = ascii_middle_boundary(text, length, position) {
        return (byte, false);
    }
    if let Some(byte) = fixed_width::three_byte_boundary(text, length, position) {
        return (byte, false);
    }
    let bytes = text.as_bytes();
    if position <= remaining {
        if bytes[..position].is_ascii() {
            return (position, false);
        }
        let mut offset = position;
        for (byte, scalar) in text.char_indices() {
            if offset == 0 {
                return (byte, false);
            }
            let width = scalar.len_utf16();
            if offset < width {
                return (byte, true);
            }
            offset -= width;
        }
    } else {
        let byte = bytes.len() - remaining;
        if bytes[byte..].is_ascii() {
            return (byte, false);
        }
        let mut offset = remaining;
        for (byte, scalar) in text.char_indices().rev() {
            let width = scalar.len_utf16();
            if offset <= width {
                return (byte, offset < width);
            }
            offset -= width;
        }
    }
    unreachable!("cached UTF-16 length must agree with well-formed UTF-8")
}

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
            Shape::WellFormed { utf16_len } => {
                let text = piece.utf8.as_str();
                if piece.is_ascii_text() {
                    return text.as_bytes().get(index).map(|byte| u16::from(*byte));
                }
                let (byte, second) = utf16_boundary(text, *utf16_len, index);
                let scalar = text[byte..].chars().next()?;
                let mut units = [0; 2];
                scalar
                    .encode_utf16(&mut units)
                    .get(usize::from(second))
                    .copied()
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
        self.with_indexed_piece(unit_index, |piece, index| match &piece.shape {
            Shape::Exact(units) => {
                // Exact storage already has random access; do not walk its
                // iterator from zero merely to read one or two units.
                let first = *units.get(index)?;
                if is_high_surrogate(first)
                    && let Some(&second) = units.get(index + 1)
                    && is_low_surrogate(second)
                {
                    let high = u32::from(first) - 0xD800;
                    let low = u32::from(second) - 0xDC00;
                    return Some(0x10000 + (high << 10) + low);
                }
                Some(u32::from(first))
            }
            Shape::WellFormed { utf16_len } => {
                let text = piece.utf8.as_str();
                if piece.is_ascii_text() {
                    return text.as_bytes().get(index).map(|byte| u32::from(*byte));
                }
                let (byte, second) = utf16_boundary(text, *utf16_len, index);
                let scalar = u32::from(text[byte..].chars().next()?);
                Some(if second {
                    0xDC00 + ((scalar - 0x10000) & 0x3FF)
                } else {
                    scalar
                })
            }
        })
    }

    /// The code units from `start` to `end` (clamped UTF-16 offsets). A
    /// boundary inside a surrogate pair preserves the lone half. Empty and
    /// whole-string slices need no materialization; other rope slices reuse
    /// covered subtrees and copy only the boundary fragments.
    pub fn utf16_slice(&self, start: usize, end: usize) -> JsString {
        let length = self.utf16_len();
        let end = end.min(length);
        let start = start.min(end);
        if start == end {
            return Self::empty();
        }
        if start == 0 && end == length {
            return self.settled();
        }
        self.slice_rope(start, end)
            .unwrap_or_else(|| self.slice_flat(start, end))
    }

    /// Visit only intersecting pieces, in order, without retaining unrelated
    /// ancestors. The work budget bounds both pointer chasing and temporary
    /// pieces, including for slices crossing a coalesced append boundary.
    /// Exhaustion falls back on the original root, settling it once instead
    /// of repeatedly walking a deep chain for sequential interior slices.
    fn slice_rope(&self, start: usize, end: usize) -> Option<Self> {
        let Text::Concat(root) = &self.utf8 else {
            return None;
        };
        if root.joined.get().is_some() {
            return None;
        }
        let mut pending = Vec::new();
        let mut piece = self.clone();
        let mut range = (start, end);
        let mut result: Option<Self> = None;
        let mut descents = 0;
        loop {
            let (start, end) = range;
            let chunk = if start == 0 && end == piece.utf16_len() {
                piece.settled()
            } else {
                if let Text::Concat(node) = &piece.utf8
                    && node.joined.get().is_none()
                    && let Some([left, right]) = node.parts()
                {
                    if descents == MAX_INDEX_DESCENT {
                        return None;
                    }
                    descents += 1;
                    let split = left.utf16_len();
                    if end <= split {
                        piece = left;
                    } else if start >= split {
                        piece = right;
                        range = (start - split, end - split);
                    } else {
                        pending.push((right, 0, end - split));
                        piece = left;
                        range = (start, split);
                    }
                    continue;
                }
                // If a concurrent join released the parts, its published
                // buffer is now available to the flat reader.
                piece.slice_flat(start, end)
            };
            result = Some(match result {
                Some(prefix) => prefix.concat(&chunk),
                None => chunk,
            });
            match pending.pop() {
                Some((next, start, end)) => {
                    piece = next;
                    range = (start, end);
                }
                None => return result,
            }
        }
    }

    /// Read a leaf, a published joined buffer, or the bounded-work fallback.
    /// Keeping this separate prevents the fallback from re-entering the
    /// rope traversal at the same root.
    fn slice_flat(&self, start: usize, end: usize) -> Self {
        match &self.shape {
            Shape::WellFormed { .. } if self.is_ascii_text() => Self {
                utf8: Text::Flat(Arc::from(&self.utf8[start..end])),
                shape: Shape::WellFormed {
                    utf16_len: end - start,
                },
            },
            Shape::WellFormed { utf16_len } => {
                let text = self.utf8.as_str();
                let (byte, second) = utf16_boundary(text, *utf16_len, start);
                let rest = &text[byte..];
                let count = end - start;
                // `rest` begins at the scalar, including its high half when
                // `start` selected the low half. Keep both coordinates in
                // that same frame so short slices never rescan the prefix.
                let skipped = usize::from(second);
                let (stop, split_end) =
                    utf16_boundary(rest, *utf16_len - start + skipped, count + skipped);
                if !second && !split_end {
                    return Self {
                        utf8: Text::Flat(Arc::from(&rest[..stop])),
                        shape: Shape::WellFormed { utf16_len: count },
                    };
                }
                // A split first/last pair proves that the result has a lone
                // surrogate. Do not try String::from_utf16 only to fail, then
                // decode the entire slice again for its lossy projection.
                // The scalar-aligned middle is already valid UTF-8: copy it
                // verbatim, replacing only the one or two broken edge units.
                let middle_start = if second {
                    rest.chars()
                        .next()
                        .expect("a split boundary has an astral scalar")
                        .len_utf8()
                } else {
                    0
                };
                let middle = &rest[middle_start..stop];
                let replacement_bytes =
                    '\u{fffd}'.len_utf8() * (skipped + usize::from(split_end));
                let mut projection = String::with_capacity(middle.len() + replacement_bytes);
                if second {
                    projection.push('\u{fffd}');
                }
                projection.push_str(middle);
                if split_end {
                    projection.push('\u{fffd}');
                }
                let units: Arc<[u16]> = rest.encode_utf16().skip(skipped).take(count).collect();
                Self {
                    utf8: Text::Flat(Arc::from(projection)),
                    shape: Shape::Exact(units),
                }
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

    #[test]
    fn empty_and_whole_slices_do_not_materialize_a_rope() {
        let rope = JsString::from("a".repeat(1100))
            .concat(&JsString::from("\u{1f600}".repeat(300)));
        let length = rope.utf16_len();
        for (start, end) in [(0, 0), (8, 3), (length, length), (usize::MAX, usize::MAX)] {
            assert!(rope.utf16_slice(start, end).is_empty());
            assert_unjoined(&rope);
        }
        let whole = rope.utf16_slice(0, usize::MAX);
        let (Text::Concat(original), Text::Concat(sliced)) = (&rope.utf8, &whole.utf8) else {
            panic!("a whole slice should share its concatenation");
        };
        assert!(Arc::ptr_eq(original, sliced));
        assert_unjoined(&rope);
    }

    #[test]
    fn append_and_prepend_slices_preserve_lazy_storage_across_piece_boundaries() {
        let texts = ["abc", "x\u{e9}", "a\u{1f600}b"];
        for prepend in [false, true] {
            let initial = "prefix".repeat(300);
            let mut expected: Vec<u16> = initial.encode_utf16().collect();
            let mut rope = JsString::from(initial);
            for round in 0..2048 {
                let text = texts[round % texts.len()];
                let piece = JsString::from(text);
                let units: Vec<u16> = text.encode_utf16().collect();
                let (start, end) = if prepend {
                    drop(expected.splice(0..0, units.iter().copied()));
                    rope = piece.concat(&rope);
                    (0, 12)
                } else {
                    expected.extend_from_slice(&units);
                    rope = rope.concat(&piece);
                    (expected.len() - 12, expected.len())
                };
                // The window extends beyond the new piece, and periodically
                // across the 1024-byte coalescing boundary, not just within
                // an immediate flat child.
                assert_eq!(
                    rope.utf16_slice(start, end).code_units_vec(),
                    expected[start..end],
                    "round={round} prepend={prepend}"
                );
                assert_eq!(
                    rope.utf16_slice(end - 1, end).code_units_vec(),
                    expected[end - 1..end]
                );
                assert_unjoined(&rope);
            }
        }
    }

    #[test]
    fn cross_piece_slices_preserve_all_utf16_boundary_kinds() {
        let texts = [
            "a".repeat(1100),
            "\u{1f600}\u{e9}".repeat(400),
            "\u{65e5}\u{1f603}".repeat(400),
            "z".repeat(1100),
        ];
        let pieces = texts.each_ref().map(|text| JsString::from(text.as_str()));
        let rope = pieces[0]
            .concat(&pieces[1])
            .concat(&pieces[2].concat(&pieces[3]));
        let expected: Vec<u16> = texts.concat().encode_utf16().collect();
        let mut positions = vec![0, 1, expected.len() - 1, expected.len()];
        let mut boundary = 0;
        for text in texts.iter().take(3) {
            boundary += text.encode_utf16().count();
            positions.extend(boundary - 3..=boundary + 3);
        }
        for &start in &positions {
            for &end in &positions {
                if start >= end || (start == 0 && end == expected.len()) {
                    continue;
                }
                let slice = rope.utf16_slice(start, end);
                assert_eq!(slice.code_units_vec(), expected[start..end], "{start}..{end}");
                assert_eq!(
                    slice.is_well_formed(),
                    String::from_utf16(&expected[start..end]).is_ok()
                );
                assert_unjoined(&rope);
            }
        }
    }

    #[test]
    fn covered_subtree_slice_shares_only_the_requested_subtree() {
        let a = JsString::from("a".repeat(1100));
        let b = JsString::from("b".repeat(1100));
        let c = JsString::from("c".repeat(1100));
        let covered = a.concat(&b);
        let rope = covered.concat(&c);
        let slice = rope.utf16_slice(0, covered.utf16_len());
        let (Text::Concat(original), Text::Concat(sliced)) = (&covered.utf8, &slice.utf8) else {
            panic!("a covered subtree should be shared, not copied");
        };
        assert!(Arc::ptr_eq(original, sliced));
        assert_eq!(slice.retained_bytes(24), covered.retained_bytes(24));
        assert!(slice.retained_bytes(24) < rope.retained_bytes(24));
        assert_unjoined(&covered);
        assert_unjoined(&rope);
    }

    #[test]
    fn deep_interior_slice_settles_the_root_once() {
        let piece = JsString::from("x".repeat(CONCAT_COPY_MAX_BYTES + 1));
        for prepend in [false, true] {
            let mut rope = piece.clone();
            for _ in 0..MAX_INDEX_DESCENT + 16 {
                rope = if prepend {
                    piece.concat(&rope)
                } else {
                    rope.concat(&piece)
                };
            }
            let start = if prepend { rope.utf16_len() - 2 } else { 1 };
            assert_unjoined(&rope);
            assert_eq!(rope.utf16_slice(start, start + 1).as_str(), Some("x"));
            let Text::Concat(node) = &rope.utf8 else {
                unreachable!()
            };
            let joined = node.joined.get().expect("bounded fallback must settle root");
            assert!(node.parts().is_none());
            assert_eq!(rope.utf16_slice(2, 4).as_str(), Some("xx"));
            assert!(Arc::ptr_eq(joined, node.joined.get().unwrap()));
        }
    }

    #[test]
    fn flat_and_exact_slices_match_clamped_code_unit_ranges() {
        let alphabet = [0x61, 0xE9, 0xD800, 0xDC00, 0xDFFF];
        for a in alphabet {
            for b in alphabet {
                for c in alphabet {
                    let units = [a, b, c];
                    let string = JsString::from_code_units(&units);
                    let positions = [0, 1, 2, 3, 4, usize::MAX];
                    for start in positions {
                        for end in positions {
                            let stop = end.min(units.len());
                            let begin = start.min(stop);
                            let slice = string.utf16_slice(start, end);
                            assert_eq!(slice.code_units_vec(), units[begin..stop]);
                            assert_eq!(
                                slice.is_well_formed(),
                                String::from_utf16(&units[begin..stop]).is_ok()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn unicode_boundaries_readers_and_slices_match_utf16_exhaustively() {
        let alphabet = ['a', '\u{e9}', '\u{20ac}', '\u{1f600}', '\u{10000}'];
        for a in alphabet {
            for b in alphabet {
                for c in alphabet {
                    for d in alphabet {
                        let text: String = [a, b, c, d].into_iter().collect();
                        let units: Vec<u16> = text.encode_utf16().collect();
                        let string = JsString::from(text.as_str());
                        for index in 0..=units.len() {
                            let (byte, second) = utf16_boundary(&text, units.len(), index);
                            assert!(text.is_char_boundary(byte));
                            assert_eq!(
                                text[..byte].encode_utf16().count() + usize::from(second),
                                index
                            );
                            if second {
                                assert_eq!(text[byte..].chars().next().unwrap().len_utf16(), 2);
                            }
                            assert_eq!(string.code_unit_at(index), units.get(index).copied());
                            assert_eq!(
                                string.code_point_at(index),
                                reference_point(&units, index)
                            );
                            for end in index..=units.len() {
                                let slice = string.utf16_slice(index, end);
                                assert_eq!(slice.code_units_vec(), units[index..end]);
                                assert_eq!(
                                    slice.is_well_formed(),
                                    String::from_utf16(&units[index..end]).is_ok()
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn long_unicode_prefixes_and_suffixes_keep_exact_offsets() {
        let texts = [
            format!("{}a\u{1f600}z", "\u{e9}\u{65e5}".repeat(4096)),
            format!("\u{1f600}{}\u{e9}", "a".repeat(8192)),
            format!("\u{e9}{}abc", "\u{1f600}".repeat(4096)),
            format!("{}\u{1f600}", "a".repeat(8192)),
        ];
        for text in texts {
            let units: Vec<u16> = text.encode_utf16().collect();
            let string = JsString::from(text.as_str());
            let midpoint = units.len() / 2;
            let positions = (0..8)
                .chain(midpoint - 3..midpoint + 3)
                .chain(units.len() - 8..=units.len());
            for start in positions {
                assert_eq!(string.code_unit_at(start), units.get(start).copied());
                assert_eq!(string.code_point_at(start), reference_point(&units, start));
                for width in [0, 1, 2, 3, 8, 64] {
                    let end = (start + width).min(units.len());
                    assert_eq!(
                        string.utf16_slice(start, end).code_units_vec(),
                        units[start..end]
                    );
                }
            }
        }
    }

    #[test]
    fn exact_storage_code_points_handle_a_long_prefix_without_lossy_projection() {
        let mut units = vec![0x61; 8192];
        units.extend_from_slice(&[0xD800, 0x62, 0xD83D, 0xDE00, 0xDC00, 0xDFFF]);
        let string = JsString::from_code_units(&units);
        assert!(!string.is_well_formed());
        for index in 8190..=units.len() {
            assert_eq!(string.code_unit_at(index), units.get(index).copied());
            assert_eq!(string.code_point_at(index), reference_point(&units, index));
        }
    }

    #[test]
    fn sparse_unicode_fringes_prove_direct_middle_access() {
        let fringes = [
            ("", "\u{1f600}"),
            ("\u{e9}", ""),
            ("\u{20ac}\u{1f600}", "\u{df}"),
            ("\u{d7ff}\u{e000}", "\u{10000}\u{10ffff}"),
        ];
        for width in [1024, 8192, 131072] {
            for (prefix, suffix) in fringes {
                let text = format!("{prefix}{}{suffix}", "a".repeat(width));
                let length = text.encode_utf16().count();
                let string = JsString::from(text.as_str());
                let excess = prefix.len() - prefix.encode_utf16().count();
                for index in [256, 512, length / 2, length - 256] {
                    // Exercise the bounded proof itself, not only an answer
                    // the old linear fallback could also produce.
                    assert_eq!(
                        ascii_middle_boundary(&text, length, index),
                        Some(index + excess)
                    );
                    assert_eq!(
                        utf16_boundary(&text, length, index),
                        (index + excess, false)
                    );
                    assert_eq!(string.code_unit_at(index), Some(u16::from(b'a')));
                    assert_eq!(string.code_point_at(index), Some(u32::from(b'a')));
                    assert_eq!(
                        string.utf16_slice(index, index + 7).as_str(),
                        Some("aaaaaaa")
                    );
                }
            }
        }
    }

    #[test]
    fn interior_unicode_cannot_pass_the_ascii_middle_proof() {
        for scalar in ['\u{e9}', '\u{20ac}', '\u{1f600}', '\u{10ffff}'] {
            let text = format!(
                "\u{e9}{}{scalar}{}\u{1f600}",
                "a".repeat(1024),
                "b".repeat(1024)
            );
            let units: Vec<u16> = text.encode_utf16().collect();
            let string = JsString::from(text.as_str());
            for index in [256, 1024, 1025, 1026, 1027, units.len() - 256] {
                assert_eq!(ascii_middle_boundary(&text, units.len(), index), None);
                assert_eq!(string.code_unit_at(index), units.get(index).copied());
                assert_eq!(string.code_point_at(index), reference_point(&units, index));
            }
        }
    }

    #[test]
    fn ascii_middle_proof_never_counts_a_split_fringe_scalar() {
        for scalar in ['\u{e9}', '\u{20ac}', '\u{1f600}'] {
            for pad in ASCII_FRINGE_BYTES - scalar.len_utf8() + 1..ASCII_FRINGE_BYTES {
                let padding = "x".repeat(pad);
                let middle = "a".repeat(2048);
                for text in [
                    format!("{padding}{scalar}{middle}"),
                    format!("{middle}{scalar}{padding}"),
                ] {
                    let units: Vec<u16> = text.encode_utf16().collect();
                    let index = units.len() / 2;
                    // The non-ASCII scalar straddles the probe boundary.
                    // Rounding inward must leave its excess unaccounted for.
                    assert_eq!(ascii_middle_boundary(&text, units.len(), index), None);
                    let (byte, second) = utf16_boundary(&text, units.len(), index);
                    assert!(!second);
                    assert_eq!(text[..byte].encode_utf16().count(), index);
                }
            }
        }
    }

    #[test]
    fn ascii_middle_proof_preserves_short_dense_and_edge_boundaries() {
        for text in [
            String::from("a\u{1f600}z"),
            "\u{e9}\u{1f600}".repeat(512),
            format!("\u{1f600}{}\u{20ac}", "a".repeat(640)),
            format!(
                "{}{}{}",
                "\u{1f600}".repeat(8),
                "a".repeat(640),
                "\u{20ac}".repeat(10)
            ),
        ] {
            let units: Vec<u16> = text.encode_utf16().collect();
            let string = JsString::from(text.as_str());
            for index in 0..=units.len() {
                let (byte, second) = utf16_boundary(&text, units.len(), index);
                assert!(text.is_char_boundary(byte));
                assert_eq!(
                    text[..byte].encode_utf16().count() + usize::from(second),
                    index
                );
                assert_eq!(string.code_unit_at(index), units.get(index).copied());
                assert_eq!(string.code_point_at(index), reference_point(&units, index));
            }
        }
    }

    #[test]
    fn split_pair_slices_match_canonical_storage_and_wire() {
        for text in [
            "\u{1f600}",
            "\u{1f600}\u{1f600}",
            "a\u{1f600}\u{e9}\u{1f600}z",
            "\u{10000}\u{fffd}\u{10ffff}",
        ] {
            let string = JsString::from(text);
            let units: Vec<u16> = text.encode_utf16().collect();
            for start in 0..=units.len() {
                for end in start..=units.len() {
                    let expected = JsString::from_code_units(&units[start..end]);
                    let actual = string.utf16_slice(start, end);
                    assert_eq!(actual, expected, "{text:?} {start}..{end}");
                    assert_eq!(
                        actual.as_utf8_projection(),
                        String::from_utf16_lossy(&units[start..end])
                    );
                    assert_eq!(
                        serde_json::to_string(&actual).unwrap(),
                        serde_json::to_string(&expected).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn long_split_pair_slices_copy_the_middle_without_renormalizing_it() {
        let text = format!("\u{1f600}{}\u{10ffff}", "a\u{e9}\u{65e5}".repeat(4096));
        let units: Vec<u16> = text.encode_utf16().collect();
        let length = units.len();
        let string = JsString::from(text.as_str());
        for (start, end) in [
            (0, length - 1),
            (1, length),
            (1, length - 1),
            (0, 1),
            (1, 2),
            (length - 1, length),
            (2, length - 2),
        ] {
            let expected = JsString::from_code_units(&units[start..end]);
            let actual = string.utf16_slice(start, end);
            assert_eq!(actual, expected, "{start}..{end}");
            assert_eq!(actual.code_units_vec(), units[start..end]);
            assert_eq!(actual.utf16_len(), end - start);
            assert_eq!(actual.retained_bytes(24), expected.retained_bytes(24));
        }
    }

    #[test]
    fn split_rope_slices_keep_ancestors_lazy_and_heal_when_rejoined() {
        let left_text = format!("{}\u{1f600}", "a".repeat(1100));
        let right_text = format!("\u{1f603}{}", "\u{e9}".repeat(600));
        let left = JsString::from(left_text.as_str());
        let right = JsString::from(right_text.as_str());
        let rope = left.concat(&right);
        let split = left.utf16_len() - 1;
        let head = rope.utf16_slice(0, split);
        let tail = rope.utf16_slice(split, rope.utf16_len());
        assert!(!head.is_well_formed());
        assert!(!tail.is_well_formed());
        assert_unjoined(&rope);
        let healed = head.concat(&tail);
        assert!(healed.is_well_formed());
        assert_eq!(
            healed.as_str(),
            Some(format!("{left_text}{right_text}").as_str())
        );
        assert_unjoined(&rope);
        let across = rope.utf16_slice(split, split + 2);
        assert_eq!(across, JsString::from_code_units(&[0xDE00, 0xD83D]));
        assert_eq!(across.as_utf8_projection(), "\u{fffd}\u{fffd}");
        assert_unjoined(&rope);
    }

    #[test]
    fn exact_source_slices_still_renormalize_after_removing_lone_edges() {
        let source = JsString::from_code_units(&[0xD800, 0x61, 0xD83D, 0xDE00, 0x62, 0xDC00]);
        assert!(!source.is_well_formed());
        let middle = source.utf16_slice(1, 5);
        assert!(middle.is_well_formed());
        assert_eq!(middle.as_str(), Some("a\u{1f600}b"));
        assert_eq!(serde_json::to_string(&middle).unwrap(), "\"a\u{1f600}b\"");
    }
}
