//! Lazy exact UTF-16 iteration over well-formed concatenation trees.
//!
//! Iteration never publishes a joined buffer. Cached subtree lengths also
//! let `nth` discard complete subtrees instead of decoding their contents.
//! This module is private to the canonical shared string implementation.

use std::sync::Arc;

use super::{JsString, Text};

impl JsString {
    /// Borrow the structure of an unresolved concatenation without joining it.
    /// The returned strings share their existing immutable backing; this call
    /// never copies their text or allocates traversal storage. Both children
    /// are well formed, so a UTF-16 surrogate pair cannot straddle the split.
    ///
    /// `None` means this value already has flat backing (possibly the lossy
    /// projection of exact units), or another reader has published its joined
    /// buffer. It is then safe to request the usual string/unit view without
    /// causing a join. Children returned before publication remain valid.
    /// Callers walking a tree must bound/charge their own traversal storage.
    pub fn unjoined_concat_children(&self) -> Option<[Self; 2]> {
        match &self.utf8 {
            Text::Concat(node) if node.joined.get().is_none() => node.parts(),
            _ => None,
        }
    }
}

/// Allocation-free until the first unit is requested. In particular,
/// constructing a CodeUnits iterator and asking for its count/length must
/// not allocate traversal state or join the root.
#[derive(Clone)]
pub(super) struct RopeUnits<'a> {
    root: &'a JsString,
    cursor: Option<Box<UnitCursor>>,
}

impl<'a> RopeUnits<'a> {
    pub(super) fn new(root: &'a JsString) -> Self {
        Self { root, cursor: None }
    }
}

impl Iterator for RopeUnits<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        self.nth(0)
    }

    fn nth(&mut self, n: usize) -> Option<u16> {
        let root = self.root;
        self.cursor
            .get_or_insert_with(|| Box::new(UnitCursor::new(root)))
            .nth(n)
    }

    fn fold<B, F>(self, init: B, f: F) -> B
    where
        F: FnMut(B, u16) -> B,
    {
        let cursor = self
            .cursor
            .unwrap_or_else(|| Box::new(UnitCursor::new(self.root)));
        (*cursor).fold(init, f)
    }
}

/// Owning leaf references avoids self-referential borrowed UTF-8 iterators.
/// `units_left` includes `low`, when a preceding call returned a high half.
#[derive(Clone)]
struct UnitCursor {
    pending: Vec<JsString>,
    leaf: Option<Arc<str>>,
    byte: usize,
    units_left: usize,
    low: Option<u16>,
    #[cfg(test)]
    decoded_scalars: usize,
}

impl UnitCursor {
    fn new(root: &JsString) -> Self {
        Self {
            pending: vec![root.clone()],
            leaf: None,
            byte: 0,
            units_left: 0,
            low: None,
            #[cfg(test)]
            decoded_scalars: 0,
        }
    }

    fn next_in_leaf(&mut self) -> Option<u16> {
        if let Some(low) = self.low.take() {
            self.units_left -= 1;
            return Some(low);
        }
        let text = self.leaf.as_ref()?;
        let scalar = text[self.byte..].chars().next()?;
        #[cfg(test)]
        {
            self.decoded_scalars += 1;
        }
        self.byte += scalar.len_utf8();
        let mut units = [0; 2];
        let encoded = scalar.encode_utf16(&mut units);
        self.low = encoded.get(1).copied();
        self.units_left -= 1;
        Some(encoded[0])
    }

    /// Position within a leaf without decoding a discarded Unicode prefix.
    /// Whole-scalar suffixes admit ASCII and three-byte BMP length proofs;
    /// other text is decoded from the nearer end. No index or cache is kept.
    fn skip_in_leaf(&mut self, mut n: usize) {
        debug_assert!(n < self.units_left);
        if n == 0 {
            return;
        }
        // A buffered low surrogate is not represented in the byte suffix.
        // Consume it before proving widths or counting backward from the end.
        if self.low.take().is_some() {
            self.units_left -= 1;
            n -= 1;
            if n == 0 {
                return;
            }
        }
        let text = self.leaf.as_ref().expect("in-range leaf skip needs a leaf");
        let suffix = &text[self.byte..];
        if suffix.len() == self.units_left {
            self.byte += n;
            self.units_left -= n;
            return;
        }
        // Three UTF-8 bytes is the maximum per UTF-16 unit. Equality proves
        // every scalar is three-byte BMP; unlike an average of two bytes,
        // this cannot be forged by mixing ASCII with wider characters.
        if self.units_left.checked_mul(3) == Some(suffix.len()) {
            self.byte += n * 3;
            self.units_left -= n;
            return;
        }
        let remaining = self.units_left - n;
        if n <= remaining {
            for _ in 0..n {
                self.next_in_leaf().expect("skip stays inside its leaf");
            }
            return;
        }
        let mut distance = remaining;
        for (byte, scalar) in suffix.char_indices().rev() {
            #[cfg(test)]
            {
                self.decoded_scalars += 1;
            }
            let width = scalar.len_utf16();
            if distance <= width {
                self.byte += byte;
                self.units_left = remaining;
                if distance < width {
                    // The requested unit is the low half. Its scalar's bytes
                    // are consumed, but the low half remains to be returned.
                    self.byte += scalar.len_utf8();
                    let mut units = [0; 2];
                    self.low = Some(scalar.encode_utf16(&mut units)[1]);
                }
                return;
            }
            distance -= width;
        }
        unreachable!("cached UTF-16 length must agree with the leaf")
    }

    // Whole-leaf folds preserve the standard library's tight UTF-8 decoder
    // instead of dispatching through the cursor once for every code unit.
    fn fold<B, F>(mut self, init: B, mut f: F) -> B
    where
        F: FnMut(B, u16) -> B,
    {
        let mut result = init;
        if let Some(low) = self.low.take() {
            result = f(result, low);
        }
        if let Some(leaf) = self.leaf.take() {
            result = leaf[self.byte..].encode_utf16().fold(result, &mut f);
        }
        while let Some(part) = self.pending.pop() {
            match part.utf8 {
                Text::Flat(text) => {
                    result = text.encode_utf16().fold(result, &mut f);
                }
                Text::Concat(node) => {
                    if let Some(joined) = node.joined.get() {
                        result = joined.encode_utf16().fold(result, &mut f);
                    } else if let Some([left, right]) = node.parts() {
                        self.pending.push(right);
                        self.pending.push(left);
                    } else {
                        result = node
                            .joined
                            .get()
                            .expect("concatenation parts are released only after publication")
                            .encode_utf16()
                            .fold(result, &mut f);
                    }
                }
            }
        }
        result
    }

    fn nth(&mut self, mut n: usize) -> Option<u16> {
        loop {
            if n < self.units_left {
                self.skip_in_leaf(n);
                return self.next_in_leaf();
            }
            n -= self.units_left;
            self.units_left = 0;
            self.low = None;
            self.leaf = None;
            self.byte = 0;

            // Skip whole subtrees before taking locks or decoding bytes.
            let part = loop {
                let part = self.pending.pop()?;
                let length = part.utf16_len();
                if n < length {
                    break part;
                }
                n -= length;
            };
            let length = part.utf16_len();
            match part.utf8 {
                Text::Flat(text) => {
                    self.leaf = Some(text);
                    self.units_left = length;
                }
                Text::Concat(node) => {
                    if let Some(joined) = node.joined.get() {
                        self.leaf = Some(Arc::clone(joined));
                        self.units_left = length;
                    } else if let Some([left, right]) = node.parts() {
                        self.pending.push(right);
                        self.pending.push(left);
                    } else {
                        // Another thread can publish between the cache check
                        // and parts(). Publication always precedes release.
                        self.leaf = Some(Arc::clone(node.joined.get().expect(
                            "concatenation parts are released only after publication",
                        )));
                        self.units_left = length;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rope(left: &str, right: &str) -> JsString {
        // Build the representation directly, so small exhaustive fixtures
        // exercise traversal rather than the concatenation-copy threshold.
        let left = JsString::from(left);
        let right = JsString::from(right);
        let shape = left.joined_shape(&right);
        JsString::joined(left, right, shape)
    }

    fn assert_unjoined(value: &JsString) {
        if let Text::Concat(node) = &value.utf8 {
            assert!(node.joined.get().is_none(), "iteration joined a rope");
        } else {
            panic!("test requires a rope");
        }
    }

    #[test]
    fn unjoined_children_preserve_exact_leaf_content_without_publication() {
        let parts = ["", "a", "é", "日", "😀", "\"\\\n"];
        for left in parts {
            for right in parts {
                let value = rope(left, right);
                let [a, b] = value.unjoined_concat_children().expect("unjoined root");
                assert_eq!(a.as_str(), Some(left));
                assert_eq!(b.as_str(), Some(right));
                assert!(a.is_well_formed() && b.is_well_formed());
                assert_eq!(a.utf16_len() + b.utf16_len(), value.utf16_len());
                assert_unjoined(&value);
            }
        }
        for flat in [
            JsString::empty(),
            JsString::from("flat😀"),
            JsString::from_code_units(&[0xd800, 0x61, 0xdc00]),
        ] {
            assert!(flat.unjoined_concat_children().is_none());
        }
    }

    #[test]
    fn unjoined_children_share_a_large_logical_dag_without_copying_it() {
        let mut value = rope(&"x".repeat(1024), &"y".repeat(1024));
        for _ in 0..16 {
            let shape = value.joined_shape(&value);
            value = JsString::joined(value.clone(), value, shape);
        }
        let [left, right] = value.unjoined_concat_children().unwrap();
        assert_eq!(value.len(), 128 * 1024 * 1024);
        assert_eq!(left.len(), 64 * 1024 * 1024);
        assert_eq!(left.utf16_len(), right.utf16_len());
        let (Text::Concat(left_node), Text::Concat(right_node)) = (&left.utf8, &right.utf8) else {
            panic!("children must retain their shared concatenation backing");
        };
        assert!(Arc::ptr_eq(left_node, right_node));
        assert_unjoined(&left);
        assert_unjoined(&right);
        assert_unjoined(&value);
    }

    #[test]
    fn returned_children_survive_parent_publication() {
        let value = rope("firsté", "second😀");
        let [left, right] = value.unjoined_concat_children().unwrap();
        assert_eq!(value.as_str(), Some("firstésecond😀"));
        assert!(value.unjoined_concat_children().is_none());
        assert_eq!(left.as_str(), Some("firsté"));
        assert_eq!(right.as_str(), Some("second😀"));
        assert_eq!(value.utf16_len(), left.utf16_len() + right.utf16_len());
    }

    #[test]
    fn unjoined_children_race_with_join_publication_without_missing_text() {
        let value = rope(&"aé".repeat(1024), &"😀z".repeat(1024));
        let expected = format!("{}{}", "aé".repeat(1024), "😀z".repeat(1024));
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for index in 0..8 {
                let value = &value;
                let expected = &expected;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    if index % 2 == 0 {
                        assert_eq!(value.as_str(), Some(expected.as_str()));
                    } else {
                        for _ in 0..64 {
                            let text = if let Some([left, right]) = value.unjoined_concat_children() {
                                format!("{}{}", left.as_str().unwrap(), right.as_str().unwrap())
                            } else {
                                value.as_str().unwrap().to_string()
                            };
                            assert_eq!(&text, expected);
                        }
                    }
                });
            }
        });
        assert!(value.unjoined_concat_children().is_none());
    }

    #[test]
    fn code_units_match_flat_utf16_for_every_small_pair_and_skip() {
        let parts = ["", "a", "\u{e9}", "\u{65e5}", "\u{1f600}", "a\u{1f600}z"];
        for left in parts {
            for right in parts {
                let value = rope(left, right);
                let expected: Vec<u16> = format!("{left}{right}").encode_utf16().collect();
                assert_eq!(value.encode_utf16().collect::<Vec<_>>(), expected);
                for consumed in 0..=expected.len() {
                    for skip in 0..=expected.len() + 1 {
                        let mut actual = value.encode_utf16();
                        for unit in &expected[..consumed] {
                            assert_eq!(actual.next(), Some(*unit));
                        }
                        let mut reference = expected[consumed..].iter().copied();
                        assert_eq!(actual.nth(skip), reference.nth(skip));
                        assert_eq!(actual.len(), reference.len());
                        assert_eq!(actual.clone().count(), reference.len());
                        assert_eq!(actual.clone().last(), reference.clone().last());
                        assert_eq!(
                            actual.clone().fold(Vec::new(), |mut units, unit| {
                                units.push(unit);
                                units
                            }),
                            reference.clone().collect::<Vec<_>>()
                        );
                        assert_eq!(actual.collect::<Vec<_>>(), reference.collect::<Vec<_>>());
                    }
                }
                let mut exhausted = value.encode_utf16();
                assert_eq!(exhausted.nth(usize::MAX), None);
                assert_eq!(exhausted.next(), None);
                assert_eq!(exhausted.len(), 0);
                assert_unjoined(&value);
            }
        }
    }

    #[test]
    fn construction_count_and_out_of_range_skip_do_not_start_traversal() {
        let value = rope("abc", "\u{1f600}");
        let iterator = value.encode_utf16();
        let super::super::CodeUnitsInner::Rope(cursor) = &iterator.inner else {
            panic!("unjoined rope must use the lazy iterator");
        };
        assert!(cursor.cursor.is_none());
        assert_eq!(iterator.clone().size_hint(), (5, Some(5)));
        assert_eq!(iterator.count(), 5);
        assert_unjoined(&value);
    }

    #[test]
    fn clone_between_surrogate_halves_has_independent_state() {
        let value = rope("\u{1f600}", "tail");
        let mut units = value.encode_utf16();
        assert_eq!(units.next(), Some(0xd83d));
        let mut cloned = units.clone();
        assert_eq!(units.next(), Some(0xde00));
        assert_eq!(cloned.nth(1), Some(u16::from(b't')));
        assert_eq!(
            units.collect::<Vec<_>>(),
            "tail".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(
            cloned.collect::<Vec<_>>(),
            "ail".encode_utf16().collect::<Vec<_>>()
        );
        assert_unjoined(&value);
    }

    #[test]
    fn a_pending_low_surrogate_cannot_prove_an_ascii_suffix() {
        let value = rope("\u{1f600}\u{e9}x", "tail");
        let mut units = value.encode_utf16();
        assert_eq!(units.next(), Some(0xd83d));
        assert_eq!(units.nth(1), Some(0xe9));
        assert_eq!(units.next(), Some(u16::from(b'x')));
        assert_eq!(units.collect::<Vec<_>>(), "tail".encode_utf16().collect::<Vec<_>>());
        assert_unjoined(&value);
    }

    #[test]
    fn nth_skips_a_large_shared_subtree_without_visiting_it() {
        let mut prefix = JsString::from("\u{1f600}");
        for _ in 0..20 {
            let shape = prefix.joined_shape(&prefix);
            prefix = JsString::joined(prefix.clone(), prefix, shape);
        }
        let suffix = JsString::from("z");
        let shape = prefix.joined_shape(&suffix);
        let value = JsString::joined(prefix.clone(), suffix, shape);
        assert_eq!(
            value.encode_utf16().nth(prefix.utf16_len()),
            Some(u16::from(b'z'))
        );
        assert_unjoined(&prefix);
        assert_unjoined(&value);
    }

    #[test]
    fn exact_lone_surrogates_and_relational_order_remain_exact() {
        let exact = JsString::from_code_units(&[0xd800, 0x61, 0xdc00]);
        assert_eq!(exact.encode_utf16().collect::<Vec<_>>(), [0xd800, 0x61, 0xdc00]);
        let left = rope("\u{1f600}", "suffix");
        let right = rope("\u{ff5a}", "suffix");
        assert_eq!(left.utf16_cmp(&right), std::cmp::Ordering::Less);
        assert_unjoined(&left);
        assert_unjoined(&right);
    }

    #[test]
    fn partially_joined_subtree_and_concurrent_publication_are_safe() {
        let left = rope("\u{e9}", "\u{1f600}");
        let right = rope("\u{65e5}", "tail");
        let shape = left.joined_shape(&right);
        let value = JsString::joined(left.clone(), right.clone(), shape);
        let expected: Vec<u16> = "\u{e9}\u{1f600}\u{65e5}tail".encode_utf16().collect();
        assert!(left.as_str().is_some());
        assert_eq!(value.encode_utf16().collect::<Vec<_>>(), expected);
        assert_unjoined(&value);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..32 {
                    assert_eq!(value.encode_utf16().collect::<Vec<_>>(), expected);
                }
            });
            scope.spawn(|| {
                assert!(right.as_str().is_some());
                assert!(value.as_str().is_some());
            });
        });
        assert_eq!(value.encode_utf16().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn deeply_skewed_iteration_uses_no_recursive_traversal() {
        let mut value = JsString::from("a");
        for _ in 0..4096 {
            let tail = JsString::from("\u{1f600}");
            let shape = value.joined_shape(&tail);
            value = JsString::joined(value, tail, shape);
        }
        assert_eq!(value.encode_utf16().fold(0_usize, |n, _| n + 1), 8193);
        assert_unjoined(&value);
    }

    #[test]
    fn near_end_unicode_skips_decode_only_the_short_suffix() {
        let text = "\u{e9}\u{1f600}\u{65e5}".repeat(32768);
        let expected: Vec<u16> = text.encode_utf16().collect();
        let value = rope(&text, "tail");
        for distance in 1..=12 {
            let index = expected.len() - distance;
            let mut cursor = UnitCursor::new(&value);
            assert_eq!(cursor.nth(index), Some(expected[index]));
            assert!(
                cursor.decoded_scalars <= distance + 1,
                "decoded {} scalars for a suffix of {distance} units",
                cursor.decoded_scalars
            );
            let rest = cursor.fold(Vec::new(), |mut units, unit| {
                units.push(unit);
                units
            });
            let mut suffix = expected[index + 1..].to_vec();
            suffix.extend("tail".encode_utf16());
            assert_eq!(rest, suffix);
            assert_unjoined(&value);
        }
    }

    #[test]
    fn three_byte_bmp_skip_uses_cached_width_not_a_prefix_scan() {
        let text = "\u{800}\u{65e5}\u{ffff}".repeat(32768);
        let expected: Vec<u16> = text.encode_utf16().collect();
        let value = rope(&text, "tail");
        for index in [1, 255, expected.len() / 2, expected.len() - 1] {
            let mut cursor = UnitCursor::new(&value);
            assert_eq!(cursor.nth(index), Some(expected[index]));
            assert_eq!(cursor.decoded_scalars, 1);
            assert_unjoined(&value);
        }
    }

    #[test]
    fn reverse_skip_handles_pending_and_selected_surrogate_halves() {
        for text in [
            format!("\u{1f600}{}\u{1f603}z", "\u{e9}x".repeat(128)),
            format!("\u{1f600}{}\u{1f603}", "a".repeat(256)),
            format!("\u{1f600}{}\u{1f603}", "\u{65e5}".repeat(256)),
        ] {
            let expected: Vec<u16> = text.encode_utf16().collect();
            let value = rope(&text, "tail");
            for distance in 1..=5 {
                let mut cursor = UnitCursor::new(&value);
                assert_eq!(cursor.nth(0), Some(expected[0]));
                assert!(cursor.low.is_some());
                let index = expected.len() - distance;
                assert_eq!(cursor.nth(index - 1), Some(expected[index]));
                assert!(cursor.decoded_scalars <= distance + 2);
                let cloned = cursor.clone();
                let rest = cursor.fold(Vec::new(), |mut units, unit| {
                    units.push(unit);
                    units
                });
                let mut suffix = expected[index + 1..].to_vec();
                suffix.extend("tail".encode_utf16());
                assert_eq!(rest, suffix);
                assert_eq!(
                    cloned.fold(Vec::new(), |mut units, unit| {
                        units.push(unit);
                        units
                    }),
                    suffix
                );
                assert_unjoined(&value);
            }
        }
    }

    #[test]
    fn every_partial_leaf_skip_matches_exact_units_for_mixed_widths() {
        let alphabet = ["a", "\u{e9}", "\u{65e5}", "\u{1f600}"];
        for a in alphabet {
            for b in alphabet {
                for c in alphabet {
                    let text = format!("{a}{b}{c}{a}{b}{c}");
                    let value = rope(&text, "\u{1f603}tail");
                    let expected: Vec<u16> = format!("{text}\u{1f603}tail")
                        .encode_utf16()
                        .collect();
                    for consumed in 0..expected.len() {
                        for index in consumed..expected.len() {
                            let mut cursor = UnitCursor::new(&value);
                            for unit in &expected[..consumed] {
                                assert_eq!(cursor.nth(0), Some(*unit));
                            }
                            assert_eq!(cursor.nth(index - consumed), Some(expected[index]));
                            let rest = cursor.fold(Vec::new(), |mut units, unit| {
                                units.push(unit);
                                units
                            });
                            assert_eq!(rest, expected[index + 1..]);
                        }
                    }
                    assert_unjoined(&value);
                }
            }
        }
    }
}
