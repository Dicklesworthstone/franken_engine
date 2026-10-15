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
    /// Insert beyond the current slot span. The density proof uses live
    /// entries, not the guest's index. Reserve before moving packed entries;
    /// refusal leaves their ownership intact for the dictionary fallback.
    pub(super) fn insert_forward_gap(&mut self, index: u32, entry: (String, V)) -> Option<V> {
        let offset = index as usize;
        match self {
            Self::Packed(entries) => {
                debug_assert!(offset > entries.len());
                if let Some(capacity) = gap_capacity(entries.len(), entries.len(), offset, 0) {
                    let mut slots = Vec::new();
                    if slots.try_reserve_exact(capacity).is_ok() && slots.capacity() <= capacity {
                        let mut prepared = Box::new(HoleyValues {
                            slots,
                            live: entries.len() + 1,
                        });
                        prepared.slots.extend(std::mem::take(entries).into_iter().map(Some));
                        prepared.slots.resize_with(offset, || None);
                        prepared.slots.push(Some(entry));
                        *self = Self::Holey(prepared);
                        return None;
                    }
                }
            }
            Self::Holey(entries) => {
                debug_assert!(offset > entries.slots.len());
                if let Some(capacity) = gap_capacity(
                    entries.live, entries.slots.len(), offset, entries.slots.capacity(),
                ) {
                    let admitted = capacity <= entries.slots.capacity()
                        || entries.slots.try_reserve_exact(capacity - entries.slots.len()).is_ok();
                    if admitted && entries.slots.capacity() <= capacity {
                        entries.slots.resize_with(offset, || None);
                        entries.slots.push(Some(entry));
                        entries.live += 1;
                        return None;
                    }
                }
            }
            Self::Dictionary(_) => {}
        }
        // No index-sized allocation, payload clone or key renumbering. Once
        // sparse, ordinary backfill does not repeatedly migrate storage.
        self.promote();
        self.insert(index, entry)
    }

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

    /// Resume after an already-visited packed prefix, or at zero for a
    /// previously holey carrier. The caller has applied any first rejection.
    pub(super) fn retain_holey(
        &mut self,
        mut cursor: usize,
        keep: &mut impl FnMut(&u32, &mut (String, V)) -> bool,
    ) {
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

// Bound zero-initialization and later tail trimming independently of the
// array's size. This is a native-work limit, not a measured tuning optimum.
const MAX_FORWARD_GAP: usize = 64;

/// Maximum admitted slot capacity after adding one live entry. Existing
/// headroom may be consumed down to half occupancy, but a new allocation
/// requires at least two-thirds occupancy. Reserving twice the live count
/// then leaves geometric headroom instead of reallocating on every gap.
/// Arithmetic refusal happens before any allocation or ownership movement.
fn gap_capacity(live: usize, span: usize, offset: usize, capacity: usize) -> Option<usize> {
    if offset.checked_sub(span)? > MAX_FORWARD_GAP {
        return None;
    }
    let required = offset.checked_add(1)?;
    let next_live = live.checked_add(1)?;
    let limit = next_live.checked_mul(2)?;
    if required > limit || capacity > limit {
        return None;
    }
    if required <= capacity {
        return Some(capacity);
    }
    let growth_threshold = next_live.checked_add(next_live / 2)?;
    (required <= growth_threshold).then_some(limit)
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

#[cfg(test)]
mod growth_tests;
