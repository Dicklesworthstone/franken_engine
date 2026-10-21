//! Operation-local reuse of complete character-class predicates.
//!
//! Each slot remembers only ASCII membership bits for one immutable class.
//! Misses use the existing predicate, including case folding, properties and
//! outer negation. Non-ASCII input goes straight to that predicate. There is
//! no eager alphabet scan, heap allocation or input/capture retention. A Run
//! owns exactly one immutable regexp, so class numbers cannot change meaning.
//! Neither lookup nor replacement touches the instruction-work allowance.

use super::{BacktrackRegExp, Run};

const CACHE_SLOTS: usize = 4;

#[derive(Clone, Copy)]
struct Entry {
    class: usize,
    known: [u64; 2],
    matched: [u64; 2],
}

#[derive(Default)]
pub(super) struct ClassMatches {
    entries: [Option<Entry>; CACHE_SLOTS],
    #[cfg(test)]
    pub(super) disabled: bool,
    #[cfg(test)]
    evaluations: usize,
    #[cfg(test)]
    hits: usize,
}

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
            return self.evaluate(regexp, class, c);
        }
        let slot = class % CACHE_SLOTS;
        let word = c as usize / 64;
        let bit = 1_u64 << (c as u32 % 64);
        if let Some(entry) = &self.entries[slot]
            && entry.class == class
            && entry.known[word] & bit != 0
        {
            #[cfg(test)]
            {
                self.hits += 1;
            }
            return entry.matched[word] & bit != 0;
        }
        let matched = self.evaluate(regexp, class, c);
        // A colliding class invalidates BOTH bitmaps. A cached false result
        // must not be confused with an untested character or another class.
        let entry = self.entries[slot].get_or_insert(Entry {
            class,
            known: [0; 2],
            matched: [0; 2],
        });
        if entry.class != class {
            *entry = Entry { class, known: [0; 2], matched: [0; 2] };
        }
        entry.known[word] |= bit;
        if matched {
            entry.matched[word] |= bit;
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
        let index = if backward { position.checked_sub(1)? } else { position };
        let &c = self.input.chars.get(index)?;
        self.class_matches.matches(self.regexp, class, c)
            .then_some(if backward { index } else { position + 1 })
    }
}

#[cfg(test)]
mod tests;
