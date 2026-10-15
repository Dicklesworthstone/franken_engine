//! Search unjoined ropes without publishing a whole-string UTF-8 buffer.
//!
//! Forward search reuses the exact-unit iterator; reverse search visits the
//! rightmost eligible subtrees first. In particular, searching for a suffix
//! after each append must not flatten and recopy the growing prefix.

use std::sync::Arc;

use super::{JsString, Text, access, search_utf16_units};

pub(super) fn index_of(haystack: &JsString, needle: &JsString, from: usize) -> Option<usize> {
    let needle = needle.code_units_vec();
    search_utf16_units(haystack.encode_utf16().skip(from), &needle, false)
        .map(|index| from + index)
}

/// `end` includes the complete needle at the last permitted starting point,
/// not merely that starting point. The caller has checked the lengths.
pub(super) fn last_index_of(
    haystack: &JsString,
    needle: &JsString,
    end: usize,
) -> Option<usize> {
    let mut needle = needle.code_units_vec();
    needle.reverse();
    let units = ReverseUnits::new(haystack).skip(haystack.utf16_len() - end);
    // First match from the right is the highest valid forward start. Searching
    // reversed exact units also permits either half of a surrogate pair.
    search_utf16_units(units, &needle, false).map(|index| end - index - needle.len())
}

/// Own leaf references rather than creating a self-referential UTF-8 iterator.
/// `units_left` includes a buffered high surrogate after returning its low half.
struct ReverseUnits {
    pending: Vec<JsString>,
    leaf: Option<Arc<str>>,
    byte_end: usize,
    units_left: usize,
    high: Option<u16>,
    #[cfg(test)]
    visited_nodes: usize,
    #[cfg(test)]
    decoded_scalars: usize,
}

impl ReverseUnits {
    fn new(root: &JsString) -> Self {
        Self {
            pending: vec![root.clone()],
            leaf: None,
            byte_end: 0,
            units_left: 0,
            high: None,
            #[cfg(test)]
            visited_nodes: 0,
            #[cfg(test)]
            decoded_scalars: 0,
        }
    }

    fn next_in_leaf(&mut self) -> Option<u16> {
        if let Some(high) = self.high.take() {
            self.units_left -= 1;
            return Some(high);
        }
        let text = self.leaf.as_ref()?;
        let scalar = text[..self.byte_end].chars().next_back()?;
        #[cfg(test)]
        {
            self.decoded_scalars += 1;
        }
        self.byte_end -= scalar.len_utf8();
        self.units_left -= 1;
        let mut units = [0; 2];
        let encoded = scalar.encode_utf16(&mut units);
        if encoded.len() == 2 {
            self.high = Some(encoded[0]);
            Some(encoded[1])
        } else {
            Some(encoded[0])
        }
    }

    /// Discard a UTF-16 suffix using the same checked boundary implementation
    /// as indexed reads. ASCII and three-byte BMP spans take constant work;
    /// mixed Unicode is scanned from the nearer end, not unconditionally
    /// from the beginning. A split pair leaves its high half buffered.
    fn skip_in_leaf(&mut self, mut n: usize) {
        debug_assert!(n < self.units_left);
        if n == 0 {
            return;
        }
        if self.high.take().is_some() {
            self.units_left -= 1;
            n -= 1;
            if n == 0 {
                return;
            }
        }
        let text = self.leaf.as_ref().expect("in-range reverse skip needs a leaf");
        let remaining = self.units_left - n;
        let (byte, split_pair) =
            access::utf16_boundary(&text[..self.byte_end], self.units_left, remaining);
        if split_pair {
            let scalar = text[byte..self.byte_end]
                .chars()
                .next()
                .expect("split UTF-16 boundary must identify an astral scalar");
            let mut units = [0; 2];
            self.high = Some(scalar.encode_utf16(&mut units)[0]);
        }
        self.byte_end = byte;
        self.units_left = remaining;
    }
}

impl Iterator for ReverseUnits {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        self.nth(0)
    }

    fn nth(&mut self, mut n: usize) -> Option<u16> {
        loop {
            if n < self.units_left {
                self.skip_in_leaf(n);
                return self.next_in_leaf();
            }
            n -= self.units_left;
            self.units_left = 0;
            self.high = None;
            self.leaf = None;
            self.byte_end = 0;

            // Discard complete subtrees without locking or inspecting bytes.
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
                    self.byte_end = text.len();
                    self.leaf = Some(text);
                    self.units_left = length;
                }
                Text::Concat(node) => {
                    #[cfg(test)]
                    {
                        self.visited_nodes += 1;
                    }
                    if let Some(joined) = node.joined.get() {
                        self.byte_end = joined.len();
                        self.leaf = Some(Arc::clone(joined));
                        self.units_left = length;
                    } else if let Some([left, right]) = node.parts() {
                        // LIFO: visit the right side first. Taking owned child
                        // references also tolerates concurrent publication.
                        self.pending.push(left);
                        self.pending.push(right);
                    } else {
                        // Another reader joined this node after the first
                        // cache check. Publication always precedes release.
                        let joined = node.joined.get().expect(
                            "concatenation parts are released only after publication",
                        );
                        self.byte_end = joined.len();
                        self.leaf = Some(Arc::clone(joined));
                        self.units_left = length;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
