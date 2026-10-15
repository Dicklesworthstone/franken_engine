//! Compare string projections without publishing concatenation buffers.
//!
//! Collection order remains UTF-8/projection-first, not ECMAScript UTF-16
//! relational order. JsString's Shape comparison still breaks projection
//! ties, including distinct lone-surrogate strings. Well-formed relational
//! comparisons reuse the frontier but select UTF-16 order at a mismatch.

use std::cmp::Ordering;
use std::sync::Arc;

use super::Text;

impl Text {
    pub(super) fn shares_storage(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Flat(left), Self::Flat(right)) => Arc::ptr_eq(left, right),
            (Self::Concat(left), Self::Concat(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    fn available_flat(&self) -> Option<&Arc<str>> {
        match self {
            Self::Flat(text) => Some(text),
            Self::Concat(node) => node.joined.get(),
        }
    }

    pub(super) fn cmp_streaming(&self, other: &Self) -> Ordering {
        if self.shares_storage(other) {
            return Ordering::Equal;
        }
        if let (Some(left), Some(right)) = (self.available_flat(), other.available_flat()) {
            return if Arc::ptr_eq(left, right) {
                Ordering::Equal
            } else {
                left.as_ref().cmp(right.as_ref())
            };
        }
        if self.len() == 0 || other.len() == 0 {
            return self.len().cmp(&other.len());
        }
        let mut left = ByteCursor::new(self);
        let mut right = ByteCursor::new(other);
        left.cmp_remaining(&mut right)
    }

    /// Exact UTF-16 order for two well-formed strings. Shared immutable
    /// subtrees prove equality in either encoding, including non-ASCII DAGs.
    /// Flat operands decode directly without the CodeUnits dispatch wrapper.
    /// Callers must keep lone-surrogate strings on their exact-unit path.
    pub(super) fn cmp_utf16_streaming(&self, other: &Self) -> Ordering {
        if self.shares_storage(other) {
            return Ordering::Equal;
        }
        if let (Some(left), Some(right)) = (self.available_flat(), other.available_flat()) {
            return if Arc::ptr_eq(left, right) {
                Ordering::Equal
            } else {
                left.encode_utf16().cmp(right.encode_utf16())
            };
        }
        if self.len() == 0 || other.len() == 0 {
            return self.len().cmp(&other.len());
        }
        let mut left = ByteCursor::new(self);
        let mut right = ByteCursor::new(other);
        left.cmp_remaining_in_order::<true>(&mut right)
    }

    pub(super) fn eq_str_streaming(&self, other: &str) -> bool {
        if self.len() != other.len() {
            return false;
        }
        if let Some(text) = self.available_flat() {
            return text.as_ref() == other;
        }
        if other.is_empty() {
            return true;
        }
        let mut cursor = ByteCursor::new(self);
        let mut compared = 0;
        while cursor.fill() {
            let bytes = cursor.flat_suffix();
            let count = bytes.len();
            if bytes != &other.as_bytes()[compared..compared + count] {
                return false;
            }
            compared += count;
            cursor.offset += count;
        }
        compared == other.len()
    }
}

/// Keep whole subtrees at the frontier until comparison needs their contents.
/// Eagerly filling two leaf cursors loses the chance to skip a shared DAG:
/// a few shared nodes can represent billions of identical bytes.
///
/// `offset` applies only to the last entry, and can be nonzero only when that
/// entry has a published flat buffer. Byte-order callers may start inside a
/// scalar. UTF-16 callers start on scalar boundaries and advance only over
/// equal byte prefixes ending at a leaf boundary, which preserves that
/// invariant on both sides. No lock survives expansion.
struct ByteCursor {
    pending: Vec<Text>,
    offset: usize,
    #[cfg(test)]
    expanded_nodes: usize,
    #[cfg(test)]
    compared_bytes: usize,
}

impl ByteCursor {
    fn new(text: &Text) -> Self {
        Self {
            pending: vec![text.clone()],
            offset: 0,
            #[cfg(test)]
            expanded_nodes: 0,
            #[cfg(test)]
            compared_bytes: 0,
        }
    }

    fn discard_consumed(&mut self) -> bool {
        while let Some(text) = self.pending.last() {
            debug_assert!(self.offset <= text.len());
            if self.offset != text.len() {
                return true;
            }
            self.pending.pop();
            self.offset = 0;
        }
        false
    }

    fn expand_front(&mut self) {
        debug_assert_eq!(self.offset, 0);
        let Some(Text::Concat(node)) = self.pending.pop() else {
            unreachable!("only an unmaterialized concatenation needs expansion");
        };
        #[cfg(test)]
        {
            self.expanded_nodes += 1;
        }
        if let Some(joined) = node.joined.get() {
            self.pending.push(Text::Flat(Arc::clone(joined)));
        } else if let Some([left, right]) = node.parts() {
            self.pending.push(right.utf8);
            self.pending.push(left.utf8);
        } else {
            // Publication can win after the cache check but before parts().
            self.pending.push(Text::Flat(Arc::clone(node.joined.get().expect(
                "concatenation parts are released only after publication",
            ))));
        }
    }

    fn fill(&mut self) -> bool {
        while self.discard_consumed() {
            if self.pending.last().and_then(Text::available_flat).is_some() {
                return true;
            }
            self.expand_front();
        }
        false
    }

    fn flat_suffix(&self) -> &[u8] {
        let text = self
            .pending
            .last()
            .and_then(Text::available_flat)
            .expect("fill supplied a flat buffer");
        &text.as_bytes()[self.offset..]
    }

    #[inline]
    fn cmp_remaining(&mut self, other: &mut Self) -> Ordering {
        self.cmp_remaining_in_order::<false>(other)
    }

    fn cmp_remaining_in_order<const UTF16: bool>(&mut self, other: &mut Self) -> Ordering {
        loop {
            match (self.discard_consumed(), other.discard_consumed()) {
                (false, false) => return Ordering::Equal,
                (false, true) => return Ordering::Less,
                (true, false) => return Ordering::Greater,
                (true, true) => {}
            }
            let left = self.pending.last().expect("nonempty frontier");
            let right = other.pending.last().expect("nonempty frontier");
            if self.offset == other.offset && left.shares_storage(right) {
                // Equality of immutable backing proves the whole remaining
                // subtree, not just its first leaf. Do not lock its children.
                self.pending.pop();
                other.pending.pop();
                self.offset = 0;
                other.offset = 0;
                continue;
            }
            match (left.available_flat(), right.available_flat()) {
                (Some(left), Some(right)) => {
                    let count = (left.len() - self.offset).min(right.len() - other.offset);
                    if self.offset != other.offset || !Arc::ptr_eq(left, right) {
                        #[cfg(test)]
                        {
                            self.compared_bytes += count;
                        }
                        let order = left.as_bytes()[self.offset..self.offset + count]
                            .cmp(&right.as_bytes()[other.offset..other.offset + count]);
                        if order != Ordering::Equal {
                            if UTF16 {
                                // Equal UTF-8 prefixes preserve scalar boundaries:
                                // at least one compared chunk ended a whole leaf.
                                // A mismatch may itself split a scalar, so decode
                                // the complete suffixes, not the byte chunks. The
                                // mismatch precedes either leaf's end; their UTF-16
                                // comparison therefore decides the whole strings.
                                debug_assert!(left.is_char_boundary(self.offset));
                                debug_assert!(right.is_char_boundary(other.offset));
                                return left[self.offset..]
                                    .encode_utf16()
                                    .cmp(right[other.offset..].encode_utf16());
                            }
                            return order;
                        }
                    }
                    self.offset += count;
                    other.offset += count;
                }
                (None, None) => {
                    // Expand the larger frontier first, allowing a child to
                    // align with a shared subtree at the other frontier.
                    if left.len() >= right.len() {
                        self.expand_front();
                    } else {
                        other.expand_front();
                    }
                }
                (None, Some(_)) => self.expand_front(),
                (Some(_), None) => other.expand_front(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_string::JsString;

    fn rope(left: &str, right: &str) -> JsString {
        let left = JsString::from(left);
        let right = JsString::from(right);
        let shape = left.joined_shape(&right);
        JsString::joined(left, right, shape)
    }

    fn assert_unjoined(value: &JsString) {
        let Text::Concat(node) = &value.utf8 else {
            panic!("test requires a rope");
        };
        assert!(node.joined.get().is_none(), "comparison joined a rope");
    }

    #[test]
    fn all_small_contents_and_different_piece_boundaries_match_flat_order() {
        let texts = [
            "", "a", "ab", "abc", "\u{e9}", "\u{65e5}", "\u{1f600}", "a\u{1f600}z",
        ];
        for left in texts {
            for right in texts {
                for left_split in (0..=left.len()).filter(|i| left.is_char_boundary(*i)) {
                    for right_split in (0..=right.len()).filter(|i| right.is_char_boundary(*i)) {
                        let a = rope(&left[..left_split], &left[left_split..]);
                        let b = rope(&right[..right_split], &right[right_split..]);
                        assert_eq!(a.cmp(&b), left.cmp(right));
                        assert_eq!(a == b, left == right);
                        assert_eq!(a == right, left == right);
                        assert_eq!(a.eq(right), left == right);
                        assert_eq!(
                            a.utf16_cmp(&b),
                            left.encode_utf16().cmp(right.encode_utf16())
                        );
                        assert_unjoined(&a);
                        assert_unjoined(&b);
                    }
                }
            }
        }
    }

    #[test]
    fn identity_and_shared_leaf_comparisons_do_not_join() {
        let prefix = JsString::from("p".repeat(8192));
        let left_tail = JsString::from("a");
        let right_tail = JsString::from("b");
        let shape = prefix.joined_shape(&left_tail);
        let a = JsString::joined(prefix.clone(), left_tail, shape.clone());
        let b = JsString::joined(prefix, right_tail, shape);
        assert_eq!(a.cmp(&a.clone()), Ordering::Equal);
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(a.utf16_cmp(&b), Ordering::Less);
        assert_unjoined(&a);
        assert_unjoined(&b);
        let unicode = rope("\u{1f600}", "tail");
        assert_eq!(unicode.utf16_cmp(&unicode.clone()), Ordering::Equal);
        assert_unjoined(&unicode);
    }

    #[test]
    fn projection_order_and_exact_units_are_not_conflated() {
        let a = JsString::from_code_units(&[0xd800]);
        let b = JsString::from_code_units(&[0xd801]);
        let replacement = JsString::from("\u{fffd}");
        assert_ne!(a, b);
        assert_ne!(a, replacement);
        assert_ne!(a, "\u{fffd}");
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(a.utf16_cmp(&b), Ordering::Less);
        let astral = rope("\u{1f600}", "");
        let bmp = rope("\u{ff5a}", "");
        assert_eq!(astral.cmp(&bmp), Ordering::Greater);
        assert_eq!(astral.utf16_cmp(&bmp), Ordering::Less);
        assert_unjoined(&astral);
        assert_unjoined(&bmp);
    }

    #[test]
    fn mixed_joined_and_unjoined_roots_keep_identical_order() {
        let a = rope("prefix", "\u{1f600}");
        let b = rope("pre", "fix\u{1f600}");
        assert!(a.as_str().is_some());
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert_eq!(b, "prefix\u{1f600}");
        assert_unjoined(&b);
    }

    #[test]
    fn ordering_and_equality_tolerate_concurrent_join_publication() {
        let a = rope("\u{e9}", "\u{1f600}");
        let b = rope("\u{e9}\u{1f600}", "");
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..64 {
                    assert_eq!(a, b);
                    assert_eq!(a.cmp(&b), Ordering::Equal);
                    assert_eq!(a.utf16_cmp(&b), Ordering::Equal);
                }
            });
            scope.spawn(|| {
                assert!(a.as_str().is_some());
                assert!(b.as_str().is_some());
            });
        });
    }

    #[test]
    fn early_mismatch_does_not_join_large_suffixes() {
        let suffix = JsString::from("x".repeat(65536));
        let a = JsString::from("a");
        let b = JsString::from("b");
        let shape = a.joined_shape(&suffix);
        let a = JsString::joined(a, suffix.clone(), shape.clone());
        let b = JsString::joined(b, suffix, shape);
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_ne!(a, "");
        assert_unjoined(&a);
        assert_unjoined(&b);
    }

    fn join(left: JsString, right: JsString) -> JsString {
        let shape = left.joined_shape(&right);
        JsString::joined(left, right, shape)
    }

    fn shared_gigabyte() -> JsString {
        // Thirty nodes, not a gigabyte allocation. Comparisons must skip
        // this identical subtree without walking its billion leaf uses.
        let mut prefix = JsString::from("x");
        for _ in 0..30 {
            prefix = join(prefix.clone(), prefix);
        }
        prefix
    }

    fn measured_order(left: &JsString, right: &JsString) -> (Ordering, usize, usize) {
        let mut left = ByteCursor::new(&left.utf8);
        let mut right = ByteCursor::new(&right.utf8);
        let order = left.cmp_remaining(&mut right);
        (
            order,
            left.expanded_nodes + right.expanded_nodes,
            left.compared_bytes + right.compared_bytes,
        )
    }

    #[test]
    fn shared_gigabyte_prefix_needs_only_two_expansions_and_one_byte() {
        let prefix = shared_gigabyte();
        assert_eq!(prefix.len(), 1 << 30);
        let left = join(prefix.clone(), JsString::from("a"));
        let right = join(prefix.clone(), JsString::from("b"));
        // Counter assertions bound the production path's actual node
        // expansions and bytes submitted to slice comparison, not timing.
        assert_eq!(measured_order(&left, &right), (Ordering::Less, 2, 1));
        assert_eq!(left.cmp(&right), Ordering::Less);
        assert_eq!(left.utf16_cmp(&right), Ordering::Less);
        assert_unjoined(&prefix);
        assert_unjoined(&left);
        assert_unjoined(&right);
    }

    #[test]
    fn shared_frontiers_align_across_different_ancestor_grouping() {
        let prefix = shared_gigabyte();
        let left = join(
            join(JsString::from("ab"), prefix.clone()),
            JsString::from("a"),
        );
        let right = join(
            JsString::from("ab"),
            join(prefix.clone(), JsString::from("b")),
        );
        let (order, expanded, bytes) = measured_order(&left, &right);
        assert_eq!(order, Ordering::Less);
        assert!(expanded <= 6, "expanded {expanded} nodes");
        assert_eq!(bytes, 3);
        assert_unjoined(&prefix);
        assert_unjoined(&left);
        assert_unjoined(&right);
    }

    #[test]
    fn shared_suffix_is_skipped_after_differently_partitioned_unicode_prefixes() {
        let suffix = shared_gigabyte();
        let left = join(rope("ab", "\u{e9}"), suffix.clone());
        let right = join(rope("a", "b\u{e9}"), suffix.clone());
        let (order, expanded, bytes) = measured_order(&left, &right);
        assert_eq!(order, Ordering::Equal);
        assert!(expanded <= 6, "expanded {expanded} nodes");
        assert_eq!(bytes, 4);
        assert_eq!(left.cmp(&right), Ordering::Equal);
        assert_unjoined(&suffix);
        assert_unjoined(&left);
        assert_unjoined(&right);
    }

    #[test]
    fn shared_backing_at_different_offsets_is_not_an_equal_frontier() {
        let backing = JsString::from("ababa");
        let mut left = ByteCursor::new(&backing.utf8);
        let mut right = ByteCursor::new(&backing.utf8);
        left.offset = 1;
        right.offset = 2;
        assert_eq!(left.cmp_remaining(&mut right), Ordering::Greater);
        assert_eq!(left.compared_bytes, 3);

        // A byte frontier need not be at a UTF-8 scalar boundary. Compare
        // byte slices, never index a str with one of these offsets.
        let unicode = JsString::from("\u{e9}\u{1f600}");
        for a in 0..=unicode.len() {
            for b in 0..=unicode.len() {
                let mut left = ByteCursor::new(&unicode.utf8);
                let mut right = ByteCursor::new(&unicode.utf8);
                left.offset = a;
                right.offset = b;
                assert_eq!(
                    left.cmp_remaining(&mut right),
                    unicode.as_bytes()[a..].cmp(&unicode.as_bytes()[b..])
                );
            }
        }
    }

    #[test]
    fn a_shared_node_published_before_comparison_still_skips_by_identity() {
        let shared = rope("\u{e9}", "\u{1f600}");
        let left = join(shared.clone(), JsString::from("a"));
        let right = join(shared.clone(), JsString::from("b"));
        assert!(shared.as_str().is_some());
        assert_eq!(measured_order(&left, &right), (Ordering::Less, 2, 1));
        assert_unjoined(&left);
        assert_unjoined(&right);
    }

    #[test]
    fn deterministic_shared_dags_match_flat_bytes_and_exact_units() {
        fn next(state: &mut u64) -> usize {
            *state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (*state >> 32) as usize
        }

        for seed in 0..16_u64 {
            let mut state = seed + 1;
            let mut values: Vec<(JsString, String)> =
                ["", "a", "b", "\0", "\u{e9}", "\u{65e5}", "\u{1f600}", "\u{ffff}"]
                    .into_iter()
                    .map(|text| (JsString::from(text), text.to_owned()))
                    .collect();
            for _ in 0..96 {
                let a = next(&mut state) % values.len();
                let b = next(&mut state) % values.len();
                if values[a].1.len() + values[b].1.len() > 4096 {
                    continue;
                }
                let text = format!("{}{}", values[a].1, values[b].1);
                let value = join(values[a].0.clone(), values[b].0.clone());
                values.push((value, text));
            }
            for _ in 0..512 {
                let a = next(&mut state) % values.len();
                let b = next(&mut state) % values.len();
                let (left, left_text) = &values[a];
                let (right, right_text) = &values[b];
                assert_eq!(left.cmp(right), left_text.cmp(right_text));
                assert_eq!(left == right, left_text == right_text);
                assert_eq!(left.eq(right_text.as_str()), left_text == right_text);
                assert_eq!(
                    left.utf16_cmp(right),
                    left_text.encode_utf16().cmp(right_text.encode_utf16())
                );
            }
            for (value, _) in &values {
                if matches!(&value.utf8, Text::Concat(_)) {
                    assert_unjoined(value);
                }
            }
        }
    }

    fn measured_utf16_order(left: &JsString, right: &JsString) -> (Ordering, usize, usize) {
        let mut left = ByteCursor::new(&left.utf8);
        let mut right = ByteCursor::new(&right.utf8);
        let order = left.cmp_remaining_in_order::<true>(&mut right);
        (
            order,
            left.expanded_nodes + right.expanded_nodes,
            left.compared_bytes + right.compared_bytes,
        )
    }

    fn shared_unicode_prefix(text: &str) -> JsString {
        let mut prefix = JsString::from(text);
        for _ in 0..28 {
            prefix = join(prefix.clone(), prefix);
        }
        prefix
    }

    #[test]
    fn utf16_order_skips_large_shared_unicode_subtrees() {
        for text in ["\u{e9}", "\u{65e5}", "\u{1f600}"] {
            // At most 28 allocated nodes, up to a GiB of logical UTF-8.
            let prefix = shared_unicode_prefix(text);
            assert_eq!(prefix.len(), text.len() * (1 << 28));
            assert_eq!(prefix.utf16_len(), text.encode_utf16().count() * (1 << 28));
            for (a, b) in [
                ("a", "b"),
                ("\u{1f600}", "\u{e000}"),
                ("\u{e000}", "\u{1f600}"),
                ("", "z"),
                ("same\u{1f600}", "same\u{1f600}"),
            ] {
                let left = join(prefix.clone(), JsString::from(a));
                let right = join(prefix.clone(), JsString::from(b));
                let expected = a.encode_utf16().cmp(b.encode_utf16());
                // The counters measure expansions and bytes submitted to byte
                // comparison. Any UTF-16 decoding is confined to these tails.
                assert_eq!(
                    measured_utf16_order(&left, &right),
                    (expected, 2, a.len().min(b.len()))
                );
                assert_eq!(left.utf16_cmp(&right), expected);
                assert_eq!(right.utf16_cmp(&left), expected.reverse());
                assert_eq!(left.cmp(&right), a.cmp(b));
                assert_unjoined(&prefix);
                assert_unjoined(&left);
                assert_unjoined(&right);
            }
        }
    }

    #[test]
    fn utf16_shared_frontiers_align_after_partitioned_unicode_prefixes() {
        let shared = shared_unicode_prefix("\u{1f600}");
        let left = join(
            join(rope("a", "\u{e9}"), shared.clone()),
            JsString::from("\u{1f600}"),
        );
        let right = join(
            rope("", "a\u{e9}"),
            join(shared.clone(), JsString::from("\u{e000}")),
        );
        let (order, expanded, bytes) = measured_utf16_order(&left, &right);
        assert_eq!(order, Ordering::Less);
        assert!(expanded <= 10, "expanded {expanded} nodes");
        assert_eq!(bytes, 6);
        assert_eq!(left.utf16_cmp(&right), Ordering::Less);
        assert_eq!(left.cmp(&right), Ordering::Greater);
        assert_unjoined(&shared);
        assert_unjoined(&left);
        assert_unjoined(&right);
    }

    #[test]
    fn utf16_mismatch_order_matches_flat_units_at_every_scalar_partition() {
        let scalars = [
            '\0', 'a', '\u{7ff}', '\u{800}', '\u{d7ff}', '\u{e000}',
            '\u{fffd}', '\u{ffff}', '\u{10000}', '\u{103ff}', '\u{10400}', '\u{10ffff}',
        ];
        for a in scalars {
            for b in scalars {
                let left_text = format!("\u{e9}{a}\u{1f600}");
                let right_text = format!("\u{e9}{b}\u{1f600}");
                let expected = left_text.encode_utf16().cmp(right_text.encode_utf16());
                for i in (0..=left_text.len()).filter(|i| left_text.is_char_boundary(*i)) {
                    for j in (0..=right_text.len()).filter(|j| right_text.is_char_boundary(*j)) {
                        let left = rope(&left_text[..i], &left_text[i..]);
                        let right = rope(&right_text[..j], &right_text[j..]);
                        assert_eq!(left.utf16_cmp(&right), expected);
                        assert_eq!(measured_utf16_order(&left, &right).0, expected);
                        assert_eq!(left.cmp(&right), left_text.cmp(&right_text));
                        assert_unjoined(&left);
                        assert_unjoined(&right);
                        // Settling only one operand must not settle the other.
                        assert_eq!(left.as_str(), Some(left_text.as_str()));
                        assert_eq!(left.utf16_cmp(&right), expected);
                        assert_unjoined(&right);
                        assert_eq!(right.as_str(), Some(right_text.as_str()));
                        assert_eq!(left.utf16_cmp(&right), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn utf16_shared_flat_storage_requires_equal_scalar_offsets() {
        let backing = JsString::from("\u{e9}\u{1f600}\u{e000}\u{1f600}");
        let text = backing.as_str().unwrap();
        let boundaries: Vec<_> = (0..=text.len()).filter(|i| text.is_char_boundary(*i)).collect();
        for &a in &boundaries {
            for &b in &boundaries {
                let mut left = ByteCursor::new(&backing.utf8);
                let mut right = ByteCursor::new(&backing.utf8);
                left.offset = a;
                right.offset = b;
                assert_eq!(
                    left.cmp_remaining_in_order::<true>(&mut right),
                    text[a..].encode_utf16().cmp(text[b..].encode_utf16())
                );
            }
        }
    }

    #[test]
    fn utf16_rope_comparisons_keep_lone_surrogates_on_the_exact_path() {
        let ropes = [rope("\u{e9}", "\u{1f600}"), rope("a", "\u{e000}"), rope("", "\u{fffd}")];
        for units in [vec![0xd800], vec![0xdbff], vec![0xdc00], vec![0xdfff], vec![0x61, 0xd800]] {
            let exact = JsString::from_code_units(&units);
            assert!(!exact.is_well_formed());
            for value in &ropes {
                let expected = value.code_units_vec().cmp(&units);
                assert_eq!(value.utf16_cmp(&exact), expected);
                assert_eq!(exact.utf16_cmp(value), expected.reverse());
                assert_unjoined(value);
            }
        }
    }
}
