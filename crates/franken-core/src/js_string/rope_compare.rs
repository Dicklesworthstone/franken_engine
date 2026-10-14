//! Compare string projections without publishing concatenation buffers.
//!
//! Collection order remains UTF-8/projection-first, not ECMAScript UTF-16
//! relational order. JsString's Shape comparison still breaks projection
//! ties, including distinct lone-surrogate strings.

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
        loop {
            match (left.fill(), right.fill()) {
                (false, false) => return Ordering::Equal,
                (false, true) => return Ordering::Less,
                (true, false) => return Ordering::Greater,
                (true, true) => {}
            }
            let left_leaf = left.leaf.as_ref().expect("fill supplied a leaf");
            let right_leaf = right.leaf.as_ref().expect("fill supplied a leaf");
            let count = (left_leaf.len() - left.offset).min(right_leaf.len() - right.offset);
            // Shared leaves at the same offset need no byte scan, even
            // when the enclosing concatenation nodes are different.
            if left.offset != right.offset || !Arc::ptr_eq(left_leaf, right_leaf) {
                let order = left_leaf.as_bytes()[left.offset..left.offset + count]
                    .cmp(&right_leaf.as_bytes()[right.offset..right.offset + count]);
                if order != Ordering::Equal {
                    return order;
                }
            }
            left.offset += count;
            right.offset += count;
        }
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
            let leaf = cursor.leaf.as_ref().expect("fill supplied a leaf");
            let bytes = &leaf.as_bytes()[cursor.offset..];
            if bytes != &other.as_bytes()[compared..compared + bytes.len()] {
                return false;
            }
            compared += bytes.len();
            cursor.offset = leaf.len();
        }
        compared == other.len()
    }
}

/// Each frame owns a shared immutable subtree. The explicit stack handles
/// skewed ropes without recursive traversal and releases locks before reads.
struct ByteCursor {
    pending: Vec<Text>,
    leaf: Option<Arc<str>>,
    offset: usize,
}

impl ByteCursor {
    fn new(text: &Text) -> Self {
        Self {
            pending: vec![text.clone()],
            leaf: None,
            offset: 0,
        }
    }

    fn fill(&mut self) -> bool {
        if self.leaf.as_ref().is_some_and(|leaf| self.offset < leaf.len()) {
            return true;
        }
        self.leaf = None;
        self.offset = 0;
        while let Some(text) = self.pending.pop() {
            let leaf = match text {
                Text::Flat(flat) => flat,
                Text::Concat(node) => {
                    if let Some(joined) = node.joined.get() {
                        Arc::clone(joined)
                    } else if let Some([left, right]) = node.parts() {
                        self.pending.push(right.utf8);
                        self.pending.push(left.utf8);
                        continue;
                    } else {
                        // Publication wins a race with our first cache read.
                        Arc::clone(node.joined.get().expect(
                            "concatenation parts are released only after publication",
                        ))
                    }
                }
            };
            if !leaf.is_empty() {
                self.leaf = Some(leaf);
                return true;
            }
        }
        false
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
                        assert_eq!(a.utf16_cmp(&b), left.encode_utf16().cmp(right.encode_utf16()));
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
}
