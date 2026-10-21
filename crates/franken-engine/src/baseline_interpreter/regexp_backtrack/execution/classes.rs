//! Operation-local reuse of complete character-class predicates.
//!
//! Four ASCII slots and two lazily populated Unicode blocks remember final
//! membership for immutable classes. Misses use the existing predicate,
//! including case folding, properties and outer negation. There is no eager
//! alphabet scan, heap allocation or input/capture retention. A Run owns one
//! immutable regexp, so class numbers cannot change meaning. Unicode churn
//! cannot evict ASCII results. Instruction-work charging remains unchanged.

use super::{BacktrackRegExp, Run};

const CACHE_SLOTS: usize = 4;
const UNICODE_CACHE_SLOTS: usize = 2;

/// A zero known bitmap already denotes an empty entry. No Option tag or
/// reserved class number is needed, even for the first lookup of class zero.
#[derive(Clone, Copy, Default)]
struct Entry {
    class: usize,
    known: [u64; 2],
    matched: [u64; 2],
}

/// One aligned block of 64 scalar values, populated only on actual misses.
/// Key by the original scalar, not its folded form: negation and Unicode
/// canonicalization are properties of the COMPLETE predicate being cached.
#[derive(Clone, Copy, Default)]
struct UnicodeEntry {
    class: usize,
    block: u32,
    known: u64,
    matched: u64,
}

#[derive(Default)]
pub(super) struct ClassMatches {
    entries: [Entry; CACHE_SLOTS],
    unicode: [UnicodeEntry; UNICODE_CACHE_SLOTS],
    #[cfg(test)]
    pub(super) disabled: bool,
    #[cfg(test)]
    evaluations: usize,
    #[cfg(test)]
    hits: usize,
}

// Keep the existing metadata ceiling, including test instrumentation. Using
// the known bits for vacancy makes room without widening the old 256B gate.
const _: () = assert!(std::mem::size_of::<ClassMatches>() <= 256);

impl ClassMatches {
    /// Cache final results rather than raw range membership: negated classes
    /// and the regexp's case-folding mode have already been applied on a miss.
    #[inline]
    pub(super) fn matches(&mut self, regexp: &BacktrackRegExp, class: usize, c: char) -> bool {
        #[cfg(test)]
        if self.disabled {
            return self.evaluate(regexp, class, c);
        }
        if !c.is_ascii() {
            return self.matches_unicode(regexp, class, c);
        }
        let slot = class % CACHE_SLOTS;
        let word = c as usize / 64;
        let bit = 1_u64 << (c as u32 % 64);
        let entry = &self.entries[slot];
        if entry.class == class && entry.known[word] & bit != 0 {
            #[cfg(test)]
            {
                self.hits += 1;
            }
            return entry.matched[word] & bit != 0;
        }
        let matched = self.evaluate(regexp, class, c);
        // A colliding class invalidates BOTH bitmaps. A cached false result
        // must not be confused with an untested character or another class.
        let entry = &mut self.entries[slot];
        if entry.class != class {
            *entry = Entry {
                class,
                known: [0; 2],
                matched: [0; 2],
            };
        }
        entry.known[word] |= bit;
        if matched {
            entry.matched[word] |= bit;
        }
        matched
    }

    fn matches_unicode(&mut self, regexp: &BacktrackRegExp, class: usize, c: char) -> bool {
        let scalar = u32::from(c);
        let block = scalar / 64;
        let slot = (class ^ block as usize) % UNICODE_CACHE_SLOTS;
        let bit = 1_u64 << (scalar % 64);
        let entry = &self.unicode[slot];
        if entry.class == class && entry.block == block && entry.known & bit != 0 {
            #[cfg(test)]
            {
                self.hits += 1;
            }
            return entry.matched & bit != 0;
        }
        let matched = self.evaluate(regexp, class, c);
        let entry = &mut self.unicode[slot];
        if entry.class != class || entry.block != block {
            *entry = UnicodeEntry {
                class,
                block,
                known: 0,
                matched: 0,
            };
        }
        entry.known |= bit;
        if matched {
            entry.matched |= bit;
        }
        matched
    }

    fn evaluate(&mut self, regexp: &BacktrackRegExp, class: usize, c: char) -> bool {
        #[cfg(test)]
        {
            self.evaluations += 1;
        }
        regexp.class_matches(&regexp.classes[class], c)
    }
}

impl Run<'_> {
    /// Mirror step()'s direction and EOF handling, with a mutable predicate
    /// cache instead of borrowing the entire Run through a matching closure.
    pub(super) fn class_step(
        &mut self,
        position: usize,
        backward: bool,
        class: usize,
    ) -> Option<usize> {
        let index = if backward {
            position.checked_sub(1)?
        } else {
            position
        };
        let &c = self.input.chars.get(index)?;
        self.class_matches
            .matches(self.regexp, class, c)
            .then_some(if backward { index } else { position + 1 })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unicode_tests;
