//! Search immutable UTF-8 leaves without joining a rope.
//!
//! Large leaves use the standard library's substring search. A byte KMP state
//! carries matches across leaves; small leaves feed that state directly, so a
//! pattern split over many leaves does not rescan a growing boundary window.
//! Failure tables are built only when streaming across a boundary is needed:
//! leaf-local hits need none. Short tables stay on the stack; long patterns
//! allocate only needle-sized scratch. Exact-only needles keep the unit search.

use std::sync::Arc;

use super::{JsString, Text, access};

const INLINE_PATTERN_BYTES: usize = 64;

/// Borrow only an already-published, well-formed needle. Do not flatten the
/// needle merely to decide whether this specialization is applicable.
pub(super) fn pattern(needle: &JsString) -> Option<&str> {
    if !needle.is_well_formed() {
        return None;
    }
    let text: &str = match &needle.utf8 {
        Text::Flat(text) => text,
        Text::Concat(node) => node.joined.get()?,
    };
    (!text.is_empty()).then_some(text)
}

/// Preserve allocation-free short searches without imposing a performance
/// cliff on longer needles. Scratch is proportional to the needle, never to
/// the haystack, including when a rope shares very large subtrees.
struct FailureTable {
    inline: [usize; INLINE_PATTERN_BYTES],
    overflow: Vec<usize>,
}

impl FailureTable {
    fn new(width: usize) -> Self {
        Self {
            inline: [0; INLINE_PATTERN_BYTES],
            overflow: if width > INLINE_PATTERN_BYTES {
                vec![0; width]
            } else {
                Vec::new()
            },
        }
    }

    fn as_slice(&self) -> &[usize] {
        if self.overflow.is_empty() {
            &self.inline
        } else {
            &self.overflow
        }
    }

    fn as_mut_slice(&mut self) -> &mut [usize] {
        if self.overflow.is_empty() {
            &mut self.inline
        } else {
            &mut self.overflow
        }
    }
}

struct Matcher<'a> {
    text: &'a str,
    failure: Option<FailureTable>,
    matched: usize,
    backwards: bool,
    #[cfg(test)]
    fed_bytes: usize,
}

impl<'a> Matcher<'a> {
    fn new(text: &'a str, backwards: bool) -> Self {
        debug_assert!(!text.is_empty());
        Self {
            text,
            failure: None,
            matched: 0,
            backwards,
            #[cfg(test)]
            fed_bytes: 0,
        }
    }

    /// A leaf-local hit needs neither O(m) preprocessing nor an allocation.
    /// Prepare at most once, only before a nonempty streaming scan. In
    /// particular, empty leaves and single-byte bulk misses leave this absent.
    fn prepare_failure(&mut self) {
        if self.failure.is_some() {
            return;
        }
        let mut failure = FailureTable::new(self.text.len());
        let mut prefix = 0;
        for index in 1..self.text.len() {
            let byte = self.byte(index);
            while prefix > 0 && byte != self.byte(prefix) {
                prefix = failure.as_slice()[prefix - 1];
            }
            if byte == self.byte(prefix) {
                prefix += 1;
            }
            failure.as_mut_slice()[index] = prefix;
        }
        self.failure = Some(failure);
    }

    fn byte(&self, index: usize) -> u8 {
        let bytes = self.text.as_bytes();
        bytes[if self.backwards {
            bytes.len() - 1 - index
        } else {
            index
        }]
    }

    /// Return the number of directional bytes consumed at the first match.
    fn scan(&mut self, bytes: &[u8]) -> Option<usize> {
        if bytes.is_empty() {
            return None;
        }
        self.prepare_failure();
        // Resolve the optional table and its inline/heap storage once per
        // span, not on every byte or every prefix fallback in the hot loop.
        let failure = self
            .failure
            .as_ref()
            .expect("streaming scan prepares its failure table")
            .as_slice();
        let pattern = self.text.as_bytes();
        let backwards = self.backwards;
        let matched = &mut self.matched;
        #[cfg(test)]
        let fed_bytes = &mut self.fed_bytes;
        let pattern_byte = |index: usize| {
            pattern[if backwards {
                pattern.len() - 1 - index
            } else {
                index
            }]
        };
        let mut feed = |&byte: &u8| {
            #[cfg(test)]
            {
                *fed_bytes += 1;
            }
            while *matched > 0 && byte != pattern_byte(*matched) {
                *matched = failure[*matched - 1];
            }
            if byte == pattern_byte(*matched) {
                *matched += 1;
            }
            if *matched == pattern.len() {
                *matched = failure[*matched - 1];
                true
            } else {
                false
            }
        };
        let found = if backwards {
            bytes.iter().rev().position(&mut feed)
        } else {
            bytes.iter().position(&mut feed)
        };
        found.map(|i| i + 1)
    }

    /// First match in traversal order, expressed as a forward byte start.
    /// A crossing match can start before this leaf; its forward end is used
    /// by the caller instead. Return directional bytes consumed in that case.
    fn in_leaf(&mut self, text: &str) -> Option<LeafMatch> {
        let bytes = text.as_bytes();
        let width = self.text.len();
        // Division avoids overflow for an arbitrarily long borrowed pattern.
        if bytes.len() / 2 < width {
            return self.scan(bytes).map(LeafMatch::Consumed);
        }
        // Only the first m-1 directional bytes can finish an incoming match.
        // They cannot contain a complete new match, so a crossing hit precedes
        // every leaf-local hit in either direction.
        let boundary = width - 1;
        if self.matched != 0 {
            let prefix = if self.backwards {
                &bytes[bytes.len() - boundary..]
            } else {
                &bytes[..boundary]
            };
            if let Some(consumed) = self.scan(prefix) {
                return Some(LeafMatch::Consumed(consumed));
            }
        }
        let local = if self.backwards {
            text.rfind(self.text)
        } else {
            text.find(self.text)
        };
        if let Some(index) = local {
            return Some(LeafMatch::Local(index));
        }
        // No full match exists. The last m-1 directional bytes determine all
        // possible matches continuing in the next leaf. Keep only KMP state,
        // not a copied suffix and not any reference to a previous leaf.
        self.matched = 0;
        let suffix = if self.backwards {
            &bytes[..boundary]
        } else {
            &bytes[bytes.len() - boundary..]
        };
        let found = self.scan(suffix);
        debug_assert!(found.is_none());
        None
    }
}

enum LeafMatch {
    Local(usize),
    Consumed(usize),
}

struct Leaf {
    text: Arc<str>,
    unit_start: usize,
    units: usize,
}

/// Own child references across concurrent joined-buffer publication. Subtrees
/// outside the requested UTF-16 interval are discarded before acquiring parts.
struct Leaves {
    pending: Vec<(JsString, usize)>,
    front: usize,
    back: usize,
    backwards: bool,
    #[cfg(test)]
    visited: usize,
}

impl Leaves {
    fn new(root: &JsString, front: usize, back: usize, backwards: bool) -> Self {
        debug_assert!(front <= back && back <= root.utf16_len());
        Self {
            pending: vec![(root.clone(), 0)],
            front,
            back,
            backwards,
            #[cfg(test)]
            visited: 0,
        }
    }
}

impl Iterator for Leaves {
    type Item = Leaf;

    fn next(&mut self) -> Option<Leaf> {
        while let Some((part, unit_start)) = self.pending.pop() {
            let units = part.utf16_len();
            if unit_start >= self.back || unit_start + units <= self.front || units == 0 {
                continue;
            }
            #[cfg(test)]
            {
                self.visited += 1;
            }
            let text = match part.utf8 {
                Text::Flat(text) => text,
                Text::Concat(node) => {
                    if let Some(text) = node.joined.get() {
                        Arc::clone(text)
                    } else if let Some([left, right]) = node.parts() {
                        let right_start = unit_start + left.utf16_len();
                        if self.backwards {
                            self.pending.push((left, unit_start));
                            self.pending.push((right, right_start));
                        } else {
                            self.pending.push((right, right_start));
                            self.pending.push((left, unit_start));
                        }
                        continue;
                    } else {
                        Arc::clone(node.joined.get().expect(
                            "concatenation parts are released only after publication",
                        ))
                    }
                }
            };
            return Some(Leaf {
                text,
                unit_start,
                units,
            });
        }
        None
    }
}

/// A successful well-formed byte match always starts/ends at a scalar boundary.
/// Decode only the nearer side of its leaf. ASCII offsets use cached lengths.
fn units_before(text: &str, byte: usize, units: usize) -> usize {
    if text.len() == units {
        byte
    } else if byte <= text.len() - byte {
        text[..byte].encode_utf16().count()
    } else {
        units - text[byte..].encode_utf16().count()
    }
}

pub(super) fn search(
    haystack: &JsString,
    pattern: &str,
    pattern_units: usize,
    front: usize,
    back: usize,
    backwards: bool,
) -> Option<usize> {
    debug_assert!(haystack.is_well_formed());
    let mut matcher = Matcher::new(pattern, backwards);
    let leaves = Leaves::new(haystack, front, back, backwards);
    for leaf in leaves {
        let begin_units = front.saturating_sub(leaf.unit_start);
        let end_units = (back - leaf.unit_start).min(leaf.units);
        let (mut begin, split_begin) = access::utf16_boundary(&leaf.text, leaf.units, begin_units);
        let (end, split_end) = access::utf16_boundary(&leaf.text, leaf.units, end_units);
        // A well-formed needle cannot start at a low surrogate or finish at
        // a high surrogate. Round inward only for this specialized search;
        // exact-only needles still use the unmodified code-unit path.
        if split_begin {
            begin += leaf.text[begin..]
                .chars()
                .next()
                .expect("split scalar")
                .len_utf8();
        }
        if begin >= end {
            continue;
        }
        let unit_start = leaf.unit_start + begin_units + usize::from(split_begin);
        let units = end_units - usize::from(split_end) - begin_units - usize::from(split_begin);
        let text = &leaf.text[begin..end];
        if let Some(found) = matcher.in_leaf(text) {
            return Some(match found {
                LeafMatch::Local(byte) => unit_start + units_before(text, byte, units),
                LeafMatch::Consumed(consumed) if backwards => {
                    unit_start + units_before(text, text.len() - consumed, units)
                }
                LeafMatch::Consumed(consumed) => {
                    unit_start + units_before(text, consumed, units) - pattern_units
                }
            });
        }
    }
    None
}

#[cfg(test)]
mod tests;
