//! Lazy exact UTF-16 iteration over well-formed concatenation trees.
//!
//! Iteration never publishes a joined buffer. Cached subtree lengths also
//! let `nth` discard complete subtrees instead of decoding their contents.
//! This module is private to the canonical shared string implementation.

use std::sync::Arc;

use super::{JsString, Text};

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
}

impl UnitCursor {
    fn new(root: &JsString) -> Self {
        Self {
            pending: vec![root.clone()],
            leaf: None,
            byte: 0,
            units_left: 0,
            low: None,
        }
    }

    fn next_in_leaf(&mut self) -> Option<u16> {
        if let Some(low) = self.low.take() {
            self.units_left -= 1;
            return Some(low);
        }
        let text = self.leaf.as_ref()?;
        let scalar = text[self.byte..].chars().next()?;
        self.byte += scalar.len_utf8();
        let mut units = [0; 2];
        let encoded = scalar.encode_utf16(&mut units);
        self.low = encoded.get(1).copied();
        self.units_left -= 1;
        Some(encoded[0])
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
                // For a complete scalar suffix, equal byte/unit lengths
                // prove ASCII without scanning. A pending low surrogate
                // must be excluded: it can cancel a later scalar's excess
                // bytes (for example, after the high half in "😀é").
                if self.low.is_none()
                    && self
                        .leaf
                        .as_ref()
                        .is_some_and(|leaf| leaf.len() - self.byte == self.units_left)
                {
                    self.byte += n;
                    self.units_left -= n;
                } else {
                    for _ in 0..n {
                        self.next_in_leaf()?;
                    }
                }
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
}
