//! Holey indexed storage. Slot position, not the mutable string spelling, owns
//! the numeric index. None is absence, never a JavaScript undefined value.
//!
//! Keep at least half of the logical slots occupied. As deletion makes this
//! uneconomic, move once to the existing dictionary. Ordinary hole repair does
//! not repack, avoiding a full migration on every delete/reinsert cycle.

use super::IndexedValues;
use std::iter::FusedIterator;

#[derive(Clone)]
pub(crate) struct HoleyValues<V> {
    pub(super) slots: Vec<Option<(String, V)>>,
    pub(super) live: usize,
}

impl<V> HoleyValues<V> {
    pub(super) fn prepare_append(&mut self) -> bool {
        if self.slots.len() < self.slots.capacity() {
            return true;
        }
        // Do not repeatedly grow and then shrink a half-empty vector by one
        // slot. Either reserve substantial headroom within the packed 2*live
        // capacity envelope, or migrate once to the dictionary.
        if self.slots.len() > self.live.saturating_add(self.live / 2) {
            return false;
        }
        let capacity = self.live.saturating_mul(2).max(1);
        self.slots.reserve_exact(capacity - self.slots.len());
        self.slots.capacity() <= capacity
    }

    pub(super) fn is_bounded(&self) -> bool {
        self.slots.len() <= self.live.saturating_mul(2)
    }

    pub(super) fn trim_tail(&mut self) {
        while self.slots.last().is_some_and(Option::is_none) {
            self.slots.pop();
        }
    }

    pub(super) fn shrink_spare_capacity(&mut self) {
        // Match packed storage's geometric capacity bound, but count LIVE
        // entries rather than holes. Never retain an old large backing after
        // its logical entries have been removed and their charges released.
        if self.slots.capacity() > self.live.saturating_mul(2) {
            self.slots.shrink_to_fit();
        }
    }
}

impl<V> IndexedValues<V> {
    pub(super) fn make_holey(&mut self) {
        let Self::Packed(entries) = self else {
            return;
        };
        let live = entries.len();
        // Allocate before moving anything. Preserve each String allocation and
        // move V without Clone, Default, sentinel values or unsafe conversion.
        let mut slots = Vec::with_capacity(live);
        slots.extend(std::mem::take(entries).into_iter().map(Some));
        *self = Self::Holey(Box::new(HoleyValues { slots, live }));
    }

    pub(super) fn retain_holey(
        &mut self,
        keep: &mut impl FnMut(&u32, &mut (String, V)) -> bool,
    ) {
        let mut cursor = 0usize;
        while let Self::Holey(entries) = self {
            if cursor >= entries.slots.len() {
                break;
            }
            let index = cursor as u32;
            let remove = entries.slots[cursor]
                .as_mut()
                .is_some_and(|entry| !keep(&index, entry));
            cursor += 1;
            if remove {
                // remove updates live count, trims capacity and may migrate to
                // the dictionary BEFORE V's destructor runs. Both a predicate
                // panic and a destructor panic leave the numeric suffix intact.
                drop(self.remove(&index));
            }
        }
        if let Self::Dictionary(entries) = self {
            // Migration happened mid-pass. Do not repeat earlier callbacks;
            // finish once in dictionary order instead of probing every hole.
            entries.retain(|index, entry| (*index as usize) < cursor || keep(index, entry));
        }
    }
}

/// Flatten skips holes, but cannot report an exact remaining size itself.
/// Each whole-carrier iterator starts with the authoritative live count.
/// The counter works for arbitrary interleaving of next and next_back.
pub(crate) struct Counted<I> {
    inner: I,
    remaining: usize,
}

impl<I> Counted<I> {
    pub(super) fn new(inner: I, remaining: usize) -> Self {
        Self { inner, remaining }
    }
}

impl<I: Iterator> Iterator for Counted<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();
        if item.is_some() {
            self.remaining -= 1;
        }
        item
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<I: DoubleEndedIterator> DoubleEndedIterator for Counted<I> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let item = self.inner.next_back();
        if item.is_some() {
            self.remaining -= 1;
        }
        item
    }
}

impl<I: Iterator> ExactSizeIterator for Counted<I> {}
impl<I: FusedIterator> FusedIterator for Counted<I> {}

#[cfg(test)]
mod tests;
