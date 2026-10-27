//! Dense numeric properties for the shared baseline property carrier.
//!
//! This is storage, not Array semantics: lengths, descriptors, prototypes,
//! labels and resource admission remain with the existing callers. Dense
//! prefixes use direct indexing; guarded front moves select a dense queue
//! with separate logical keys. Interior deletion keeps bounded holey slots.
//! Nearby forward gaps can also use bounded holey slots. Distant gaps and
//! sufficiently sparse storage use the dictionary without index-sized allocation.
//! No Value is cloned or replaced with undefined.

use std::collections::{BTreeMap, btree_map, vec_deque};
use std::fmt;
use std::ops::Range;
use std::slice;
use std::vec;

mod holey;
use holey::{Counted, HoleyValues};
mod queue;
use queue::QueueValues;

#[derive(Clone)]
pub(super) enum IndexedValues<V> {
    Packed(Vec<(String, V)>),
    // Boxed so ordinary packed arrays keep their original carrier size.
    Queue(Box<QueueValues<V>>),
    Holey(Box<HoleyValues<V>>),
    Dictionary(BTreeMap<u32, (String, V)>),
}

/// Leave geometric headroom when reducing an indexed backing allocation.
/// Both callers retain their existing shrink trigger and live-entry bound.
/// Shrinking to the exact span lets one append grow the backing again; two
/// tail removals then shrink it again, making a linear drain request quadratic
/// relocation work. A target between live and 2*live separates those thresholds.
/// Holes still own positions, so never shrink below the occupied slot span.
/// No removed value is retained in the spare, uninitialized capacity.
fn shrink_target(live: usize, span: usize) -> usize {
    debug_assert!(live <= span && span <= live.saturating_mul(2));
    span.max(live.saturating_add(live / 2))
}

impl<V> IndexedValues<V> {
    pub(super) fn new() -> Self {
        Self::Packed(Vec::new())
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Packed(entries) => entries.len(),
            Self::Queue(entries) => entries.len(),
            Self::Holey(entries) => entries.live,
            Self::Dictionary(entries) => entries.len(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub(super) fn get(&self, index: &u32) -> Option<(&String, &V)> {
        match self {
            Self::Packed(entries) => entries.get(*index as usize).map(|(key, value)| (key, value)),
            Self::Queue(entries) => Some((
                entries.keys.get(*index as usize)?,
                entries.values.get(*index as usize)?,
            )),
            Self::Holey(entries) => entries
                .slots
                .get(*index as usize)?
                .as_ref()
                .map(|(key, value)| (key, value)),
            Self::Dictionary(entries) => entries.get(index).map(|(key, value)| (key, value)),
        }
    }

    #[inline]
    pub(super) fn get_mut(&mut self, index: &u32) -> Option<(&mut String, &mut V)> {
        match self {
            Self::Packed(entries) => entries
                .get_mut(*index as usize)
                .map(|(key, value)| (key, value)),
            Self::Queue(entries) => Some((
                entries.keys.get_mut(*index as usize)?,
                entries.values.get_mut(*index as usize)?,
            )),
            Self::Holey(entries) => entries
                .slots
                .get_mut(*index as usize)?
                .as_mut()
                .map(|(key, value)| (key, value)),
            Self::Dictionary(entries) => entries.get_mut(index).map(|(key, value)| (key, value)),
        }
    }

    pub(super) fn contains_key(&self, index: &u32) -> bool {
        self.get(index).is_some()
    }

    /// Preserve the original key allocation when replacing an existing value,
    /// as OrderedStringMap's previous BTreeMap Entry implementation did.
    pub(super) fn insert(&mut self, index: u32, (key, value): (String, V)) -> Option<V> {
        match self {
            Self::Packed(entries) => {
                let offset = index as usize;
                if let Some((_, slot)) = entries.get_mut(offset) {
                    return Some(std::mem::replace(slot, value));
                }
                if offset == entries.len() {
                    entries.push((key, value));
                    return None;
                }
                // Admit nearby gaps by live occupancy before reserving slots.
                // Distant writes still go straight to the sparse dictionary.
                self.insert_forward_gap(index, (key, value))
            }
            Self::Queue(entries) => {
                let offset = index as usize;
                if let Some(slot) = entries.values.get_mut(offset) {
                    return Some(std::mem::replace(slot, value));
                }
                if offset == entries.len() {
                    entries.keys.reserve(1);
                    entries.values.reserve(1);
                    entries.keys.push(key);
                    entries.values.push_back(value);
                    return None;
                }
                self.queue_to_packed();
                self.insert_forward_gap(index, (key, value))
            }
            Self::Holey(entries) => {
                let offset = index as usize;
                if let Some(slot) = entries.slots.get_mut(offset) {
                    if let Some((_, stored)) = slot {
                        return Some(std::mem::replace(stored, value));
                    }
                    *slot = Some((key, value));
                    entries.live += 1;
                    return None;
                }
                if offset == entries.slots.len() && entries.prepare_append() {
                    entries.slots.push(Some((key, value)));
                    entries.live += 1;
                    return None;
                }
                if offset > entries.slots.len() {
                    return self.insert_forward_gap(index, (key, value));
                }
                self.promote();
                self.insert(index, (key, value))
            }
            Self::Dictionary(entries) => match entries.entry(index) {
                btree_map::Entry::Occupied(mut entry) => {
                    Some(std::mem::replace(&mut entry.get_mut().1, value))
                }
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((key, value));
                    None
                }
            },
        }
    }

    pub(super) fn remove(&mut self, index: &u32) -> Option<(String, V)> {
        match self {
            Self::Packed(entries) => {
                let offset = *index as usize;
                if offset >= entries.len() {
                    return None;
                }
                if offset == entries.len() - 1 {
                    let removed = entries.pop();
                    // Logical removal releases the caller's existing charge.
                    // Do not retain a formerly huge buffer after a pop drain.
                    // Keep headroom inside the same bound, so append/two-pop
                    // cycles cannot shrink to full and immediately grow again.
                    if entries.is_empty() {
                        *entries = Vec::new();
                    } else if entries.len() < entries.capacity() / 2 {
                        entries.shrink_to(shrink_target(entries.len(), entries.len()));
                        // Shrinking is best-effort. If the allocator retains
                        // surplus beyond the old bound, keep the old request.
                        if entries.len() < entries.capacity() / 2 {
                            entries.shrink_to_fit();
                        }
                    }
                    return removed;
                }
                // Move slots once rather than creating N tree entries.
                self.make_holey();
                self.remove(index)
            }
            Self::Queue(entries) => {
                let offset = *index as usize;
                if offset >= entries.len() {
                    return None;
                }
                if offset == entries.len() - 1 {
                    let removed = entries.keys.pop().zip(entries.values.pop_back());
                    entries.shrink_spare_capacity();
                    if entries.len() == 0 {
                        self.clear();
                    }
                    return removed;
                }
                self.queue_to_packed();
                self.make_holey();
                self.remove(index)
            }
            Self::Holey(entries) => {
                let removed = entries.slots.get_mut(*index as usize)?.take()?;
                entries.live -= 1;
                entries.trim_tail();
                if entries.live == 0 {
                    self.clear();
                } else if !entries.is_bounded() {
                    self.promote();
                } else {
                    entries.shrink_spare_capacity();
                }
                // Normalize before returning: dropping V may panic in callers.
                Some(removed)
            }
            Self::Dictionary(entries) => entries.remove(index),
        }
    }

    pub(super) fn clear(&mut self) {
        *self = Self::new();
    }

    /// Visit every entry once in numeric order. An all-keep pass leaves packed
    /// storage (and its allocation) alone. The first interior rejection moves
    /// to bounded holey slots, preserving direct indexing unless genuinely
    /// sparse. Callbacks can panic without reindexing the unvisited suffix.
    /// Successful filtering can recover a dense prefix; ordinary
    /// insertion/deletion still never oscillates between storage forms.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&u32, &mut (String, V)) -> bool) {
        if self.is_empty() {
            self.clear();
            return;
        }
        self.queue_to_packed();
        if matches!(self, Self::Holey(_)) {
            self.retain_holey(0, &mut keep);
        } else if let Self::Packed(entries) = self {
            let first_removed = entries.iter_mut().enumerate().find_map(|(index, entry)| {
                let index = index as u32;
                (!keep(&index, entry)).then_some(index)
            });
            let Some(first_removed) = first_removed else {
                return;
            };
            if first_removed as usize == entries.len() - 1 {
                drop(self.remove(&first_removed));
                return;
            }
            self.make_holey();
            // Apply the already-evaluated rejection before another callback.
            // Rechecking it would duplicate side effects, and delaying it
            // would leave the wrong partial map if the next callback panics.
            drop(self.remove(&first_removed));
            // The rejected index is interior, so the successor cannot overflow.
            // Resume after the visited prefix instead of invoking it twice or
            // building a dictionary for a single hole in a dense array.
            self.retain_holey(first_removed as usize + 1, &mut keep);
        } else if let Self::Dictionary(entries) = self {
            entries.retain(keep);
        }
        self.repack_dense_prefix();
    }

    /// Recovery belongs to the already-linear retain operation, not to each
    /// sparse write or hole repair. Unique ordered keys from zero through
    /// len-1 prove density without a scan or key parsing. Reserve before moving
    /// anything: inability to allocate this optional representation leaves
    /// the successfully filtered dictionary intact. Values and keys move;
    /// neither requires Clone, and no index-sized sparse allocation occurs.
    fn repack_dense_prefix(&mut self) {
        if let Self::Holey(entries) = self {
            if entries.live != entries.slots.len() {
                return;
            }
            let mut packed = Vec::new();
            if packed.try_reserve_exact(entries.live).is_err() {
                return;
            }
            packed.extend(std::mem::take(&mut entries.slots).into_iter().flatten());
            *self = Self::Packed(packed);
            return;
        }
        let Self::Dictionary(entries) = self else {
            return;
        };
        if entries.is_empty() {
            self.clear();
            return;
        }
        let Ok(last) = u32::try_from(entries.len() - 1) else {
            return;
        };
        if entries.first_key_value().is_none_or(|(key, _)| *key != 0)
            || entries.last_key_value().is_none_or(|(key, _)| *key != last)
        {
            return;
        }
        let mut packed = Vec::new();
        if packed.try_reserve_exact(entries.len()).is_err() {
            return;
        }
        packed.extend(std::mem::take(entries).into_values());
        *self = Self::Packed(packed);
    }

    /// The map contains exactly 0..len, independently of its storage form.
    pub(super) fn is_dense_prefix(&self, len: u32) -> bool {
        if self.len() != len as usize {
            return false;
        }
        match self {
            Self::Packed(_) | Self::Queue(_) => true,
            Self::Holey(entries) => entries.slots.len() == len as usize,
            Self::Dictionary(entries) => {
                len == 0
                    || (entries.first_key_value().is_some_and(|(key, _)| *key == 0)
                        && entries.last_key_value().is_some_and(|(key, _)| *key == len - 1))
            }
        }
    }

    pub(super) fn values(&self) -> Values<'_, V> {
        match self {
            Self::Packed(entries) => Values::Packed(entries.iter()),
            Self::Queue(entries) => Values::Queue(entries.keys.iter().zip(entries.values.iter())),
            Self::Holey(entries) => Values::Holey(Counted::new(
                entries.slots.iter().flatten(), entries.live,
            )),
            Self::Dictionary(entries) => Values::Dictionary(entries.values()),
        }
    }

    pub(super) fn values_mut(&mut self) -> ValuesMut<'_, V> {
        match self {
            Self::Packed(entries) => ValuesMut::Packed(entries.iter_mut()),
            Self::Queue(entries) => {
                ValuesMut::Queue(entries.keys.iter_mut().zip(entries.values.iter_mut()))
            }
            Self::Holey(entries) => ValuesMut::Holey(Counted::new(
                entries.slots.iter_mut().flatten(), entries.live,
            )),
            Self::Dictionary(entries) => ValuesMut::Dictionary(entries.values_mut()),
        }
    }

    /// Mutable values in the half-open numeric range, including absent bounds.
    /// Every caller is a guarded dense move; returning values rather than
    /// synthetic key references also avoids storing a redundant u32 per slot.
    pub(super) fn range_values_mut(&mut self, range: Range<u32>) -> RangeValuesMut<'_, V> {
        assert!(range.start <= range.end, "range start exceeds range end");
        match self {
            Self::Packed(entries) => {
                let start = (range.start as usize).min(entries.len());
                let end = (range.end as usize).min(entries.len());
                RangeValuesMut::Packed(entries[start..end].iter_mut())
            }
            Self::Queue(entries) => {
                let start = (range.start as usize).min(entries.len());
                let end = (range.end as usize).min(entries.len());
                RangeValuesMut::Queue(
                    entries.keys[start..end]
                        .iter_mut()
                        .zip(entries.values.range_mut(start..end)),
                )
            }
            Self::Holey(entries) => {
                let start = (range.start as usize).min(entries.slots.len());
                let end = (range.end as usize).min(entries.slots.len());
                RangeValuesMut::Holey(entries.slots[start..end].iter_mut().flatten())
            }
            Self::Dictionary(entries) => RangeValuesMut::Dictionary(entries.range_mut(range)),
        }
    }

    pub(super) fn into_values(self) -> IntoValues<V> {
        match self {
            Self::Packed(entries) => IntoValues::Packed(entries.into_iter()),
            Self::Queue(entries) => IntoValues::Queue(entries.keys.into_iter().zip(entries.values)),
            Self::Holey(entries) => {
                let HoleyValues { slots, live } = *entries;
                IntoValues::Holey(Counted::new(slots.into_iter().flatten(), live))
            }
            Self::Dictionary(entries) => IntoValues::Dictionary(entries.into_values()),
        }
    }

    fn promote(&mut self) {
        self.queue_to_packed();
        if let Self::Holey(entries) = self {
            let dictionary = std::mem::take(&mut entries.slots)
                .into_iter()
                .enumerate()
                .filter_map(|(index, entry)| entry.map(|entry| (index as u32, entry)))
                .collect();
            *self = Self::Dictionary(dictionary);
            return;
        }
        if let Self::Packed(entries) = self {
            let dictionary = std::mem::take(entries)
                .into_iter()
                .enumerate()
                .map(|(index, entry)| (index as u32, entry))
                .collect();
            *self = Self::Dictionary(dictionary);
        }
    }
}

// Storage history must not change map equality or the historical Debug shape.
impl<V: PartialEq> PartialEq for IndexedValues<V> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Queue(left), _) => {
                u32::try_from(left.len()).is_ok_and(|len| other.is_dense_prefix(len))
                    && left.keys.iter().zip(left.values.iter()).eq(other.values())
            }
            (_, Self::Queue(right)) => {
                u32::try_from(right.len()).is_ok_and(|len| self.is_dense_prefix(len))
                    && self.values().eq(right.keys.iter().zip(right.values.iter()))
            }
            (Self::Packed(left), Self::Packed(right)) => left == right,
            (Self::Holey(left), Self::Holey(right)) => {
                left.live == right.live && left.slots == right.slots
            }
            (Self::Holey(holey), Self::Packed(packed))
            | (Self::Packed(packed), Self::Holey(holey)) => {
                packed.len() == holey.live
                    && packed.len() == holey.slots.len()
                    && packed.iter().eq(holey.slots.iter().flatten())
            }
            (Self::Holey(holey), Self::Dictionary(dictionary))
            | (Self::Dictionary(dictionary), Self::Holey(holey)) => {
                holey.live == dictionary.len()
                    && holey.slots.iter().enumerate()
                        .filter_map(|(index, entry)| entry.as_ref().map(|value| (index as u32, value)))
                        .eq(dictionary.iter().map(|(index, value)| (*index, value)))
            }
            (Self::Dictionary(left), Self::Dictionary(right)) => left == right,
            (Self::Packed(packed), Self::Dictionary(dictionary))
            | (Self::Dictionary(dictionary), Self::Packed(packed)) => {
                packed.len() == dictionary.len()
                    && packed.iter().enumerate().zip(dictionary.iter()).all(
                        |((index, value), (key, other))| index as u32 == *key && value == other,
                    )
            }
        }
    }
}

impl<V: fmt::Debug> fmt::Debug for IndexedValues<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packed(entries) => formatter
                .debug_map()
                .entries(entries.iter().enumerate())
                .finish(),
            Self::Queue(entries) => formatter
                .debug_map()
                .entries(entries.keys.iter().zip(entries.values.iter()).enumerate())
                .finish(),
            Self::Holey(entries) => formatter.debug_map().entries(
                entries.slots.iter().enumerate()
                    .filter_map(|(index, entry)| entry.as_ref().map(|value| (index, value))),
            ).finish(),
            Self::Dictionary(entries) => fmt::Debug::fmt(entries, formatter),
        }
    }
}

type HoleyValueIter<'a, V> = Counted<std::iter::Flatten<slice::Iter<'a, Option<(String, V)>>>>;
type HoleyValueIterMut<'a, V> = Counted<std::iter::Flatten<slice::IterMut<'a, Option<(String, V)>>>>;
type HoleyValueIntoIter<V> = Counted<std::iter::Flatten<vec::IntoIter<Option<(String, V)>>>>;

pub(super) enum Values<'a, V> {
    Packed(slice::Iter<'a, (String, V)>),
    Queue(std::iter::Zip<slice::Iter<'a, String>, vec_deque::Iter<'a, V>>),
    Holey(HoleyValueIter<'a, V>),
    Dictionary(btree_map::Values<'a, u32, (String, V)>),
}

impl<'a, V> Iterator for Values<'a, V> {
    type Item = (&'a String, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next().map(|(key, value)| (key, value)),
            Self::Queue(entries) => entries.next(),
            Self::Holey(entries) => entries.next().map(|(key, value)| (key, value)),
            Self::Dictionary(entries) => entries.next().map(|(key, value)| (key, value)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Packed(entries) => entries.size_hint(),
            Self::Queue(entries) => entries.size_hint(),
            Self::Holey(entries) => entries.size_hint(),
            Self::Dictionary(entries) => entries.size_hint(),
        }
    }
}

impl<V> DoubleEndedIterator for Values<'_, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next_back().map(|(key, value)| (key, value)),
            Self::Queue(entries) => entries.next_back(),
            Self::Holey(entries) => entries.next_back().map(|(key, value)| (key, value)),
            Self::Dictionary(entries) => entries.next_back().map(|(key, value)| (key, value)),
        }
    }
}

impl<V> ExactSizeIterator for Values<'_, V> {}
impl<V> std::iter::FusedIterator for Values<'_, V> {}

pub(super) enum ValuesMut<'a, V> {
    Packed(slice::IterMut<'a, (String, V)>),
    Queue(std::iter::Zip<slice::IterMut<'a, String>, vec_deque::IterMut<'a, V>>),
    Holey(HoleyValueIterMut<'a, V>),
    Dictionary(btree_map::ValuesMut<'a, u32, (String, V)>),
}

impl<'a, V> Iterator for ValuesMut<'a, V> {
    type Item = (&'a mut String, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next().map(|(key, value)| (key, value)),
            Self::Queue(entries) => entries.next(),
            Self::Holey(entries) => entries.next().map(|(key, value)| (key, value)),
            Self::Dictionary(entries) => entries.next().map(|(key, value)| (key, value)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Packed(entries) => entries.size_hint(),
            Self::Queue(entries) => entries.size_hint(),
            Self::Holey(entries) => entries.size_hint(),
            Self::Dictionary(entries) => entries.size_hint(),
        }
    }
}

impl<V> DoubleEndedIterator for ValuesMut<'_, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next_back().map(|(key, value)| (key, value)),
            Self::Queue(entries) => entries.next_back(),
            Self::Holey(entries) => entries.next_back().map(|(key, value)| (key, value)),
            Self::Dictionary(entries) => entries.next_back().map(|(key, value)| (key, value)),
        }
    }
}

impl<V> ExactSizeIterator for ValuesMut<'_, V> {}
impl<V> std::iter::FusedIterator for ValuesMut<'_, V> {}

pub(super) enum RangeValuesMut<'a, V> {
    Packed(slice::IterMut<'a, (String, V)>),
    Queue(std::iter::Zip<slice::IterMut<'a, String>, vec_deque::IterMut<'a, V>>),
    Holey(std::iter::Flatten<slice::IterMut<'a, Option<(String, V)>>>),
    Dictionary(btree_map::RangeMut<'a, u32, (String, V)>),
}

impl<'a, V> Iterator for RangeValuesMut<'a, V> {
    type Item = (&'a mut String, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next().map(|(key, value)| (key, value)),
            Self::Queue(entries) => entries.next(),
            Self::Holey(entries) => entries.next().map(|(key, value)| (key, value)),
            Self::Dictionary(entries) => entries.next().map(|(_, (key, value))| (key, value)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Packed(entries) => entries.size_hint(),
            Self::Queue(entries) => entries.size_hint(),
            Self::Holey(entries) => entries.size_hint(),
            Self::Dictionary(entries) => entries.size_hint(),
        }
    }
}

impl<V> DoubleEndedIterator for RangeValuesMut<'_, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next_back().map(|(key, value)| (key, value)),
            Self::Queue(entries) => entries.next_back(),
            Self::Holey(entries) => entries.next_back().map(|(key, value)| (key, value)),
            Self::Dictionary(entries) => entries.next_back().map(|(_, (key, value))| (key, value)),
        }
    }
}

impl<V> std::iter::FusedIterator for RangeValuesMut<'_, V> {}

pub(super) enum IntoValues<V> {
    Packed(vec::IntoIter<(String, V)>),
    Queue(std::iter::Zip<vec::IntoIter<String>, vec_deque::IntoIter<V>>),
    Holey(HoleyValueIntoIter<V>),
    Dictionary(btree_map::IntoValues<u32, (String, V)>),
}

impl<V> Iterator for IntoValues<V> {
    type Item = (String, V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next(),
            Self::Queue(entries) => entries.next(),
            Self::Holey(entries) => entries.next(),
            Self::Dictionary(entries) => entries.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Packed(entries) => entries.size_hint(),
            Self::Queue(entries) => entries.size_hint(),
            Self::Holey(entries) => entries.size_hint(),
            Self::Dictionary(entries) => entries.size_hint(),
        }
    }
}

impl<V> DoubleEndedIterator for IntoValues<V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next_back(),
            Self::Queue(entries) => entries.next_back(),
            Self::Holey(entries) => entries.next_back(),
            Self::Dictionary(entries) => entries.next_back(),
        }
    }
}

impl<V> ExactSizeIterator for IntoValues<V> {}
impl<V> std::iter::FusedIterator for IntoValues<V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::rc::Rc;

    fn dense(len: u32) -> IndexedValues<u64> {
        let mut values = IndexedValues::new();
        for index in 0..len {
            assert_eq!(
                values.insert(index, (index.to_string(), u64::from(index))),
                None
            );
        }
        values
    }

    #[test]
    fn dense_reads_updates_and_pop_drain_stay_packed() {
        let mut values = dense(4096);
        for index in 0..4096 {
            assert_eq!(values.get(&index).map(|entry| *entry.1), Some(u64::from(index)));
            assert_eq!(
                values.insert(index, (index.to_string(), 7)),
                Some(u64::from(index))
            );
        }
        assert!(matches!(values, IndexedValues::Packed(_)));
        assert_eq!(values.get(&4096), None);
        assert_eq!(values.get(&u32::MAX), None);
        assert_eq!(values.remove(&u32::MAX), None);
        for index in (0..4096).rev() {
            assert_eq!(values.remove(&index), Some((index.to_string(), 7)));
            let IndexedValues::Packed(entries) = &values else {
                panic!("tail deletion must not promote");
            };
            if entries.is_empty() {
                assert_eq!(entries.capacity(), 0);
            }
        }
        assert!(values.is_empty());
        assert!(values.is_dense_prefix(0));
        values.insert(0, ("0".into(), 9));
        assert!(matches!(values, IndexedValues::Packed(_)));
    }

    #[test]
    fn sparse_writes_and_interior_deletes_keep_original_numeric_keys() {
        let mut values = dense(5);
        assert_eq!(values.remove(&1), Some(("1".into(), 1)));
        assert!(matches!(values, IndexedValues::Holey(_)));
        assert_eq!(values.get(&1), None);
        assert_eq!(values.get(&2).map(|entry| *entry.1), Some(2));
        assert!(!values.is_dense_prefix(4));
        values.insert(1, ("1".into(), 1));
        assert!(values.is_dense_prefix(5));
        // Repairing a hole does not repeatedly migrate the representation.
        assert!(matches!(values, IndexedValues::Holey(_)));
        values.insert(u32::MAX - 1, ((u32::MAX - 1).to_string(), 88));
        assert_eq!(values.len(), 6);
        assert_eq!(values.get(&(u32::MAX - 1)).map(|entry| *entry.1), Some(88));
        assert_eq!(
            values.values().map(|entry| entry.0.as_str()).collect::<Vec<_>>(),
            ["0", "1", "2", "3", "4", "4294967294"]
        );
        values.clear();
        assert!(matches!(values, IndexedValues::Packed(_)));
        assert_eq!(values.len(), 0);
    }

    #[test]
    fn equal_content_and_debug_do_not_depend_on_storage_history() {
        for len in 0..20 {
            let packed = dense(len);
            let mut dictionary = packed.clone();
            dictionary.promote();
            assert_eq!(packed, dictionary);
            assert_eq!(dictionary, packed);
            assert_eq!(format!("{packed:?}"), format!("{dictionary:?}"));
            assert_eq!(
                packed.values().collect::<Vec<_>>(),
                dictionary.values().collect::<Vec<_>>()
            );
            assert_eq!(
                packed.clone().into_values().collect::<Vec<_>>(),
                dictionary.clone().into_values().collect::<Vec<_>>()
            );
            assert!(packed.is_dense_prefix(len));
            assert!(dictionary.is_dense_prefix(len));
            assert!(!packed.is_dense_prefix(len + 1));
            if len > 0 {
                *dictionary.get_mut(&0).unwrap().1 = 99;
                assert_ne!(packed, dictionary);
            }
        }
    }

    #[test]
    fn iterator_front_back_and_mutable_ranges_match_dictionary() {
        for len in 0..12 {
            for start in 0..=len + 1 {
                for end in start..=len + 2 {
                    let mut packed = dense(len);
                    let mut dictionary = packed.clone();
                    dictionary.promote();
                    for values in [&mut packed, &mut dictionary] {
                        for (_, value) in values.range_values_mut(start..end) {
                            *value += 100;
                        }
                        for (_, value) in values.values_mut().rev() {
                            *value += 1;
                        }
                    }
                    assert_eq!(packed, dictionary, "len={len}, range={start}..{end}");
                    let mut front = packed.values();
                    let mut back = dictionary.values();
                    for step in 0..=len + 1 {
                        assert_eq!(front.len(), back.len());
                        let (left, right) = if step % 2 == 0 {
                            (front.next(), back.next())
                        } else {
                            (front.next_back(), back.next_back())
                        };
                        assert_eq!(left, right);
                        assert_eq!(front.len(), back.len());
                    }
                    assert_eq!(front.next(), None);
                    assert_eq!(back.next_back(), None);
                }
            }
        }
    }

    #[test]
    fn retain_calls_predicate_once_in_index_order_and_preserves_holes() {
        let mut values = dense(9);
        let mut seen = Vec::new();
        values.retain(|index, (_, value)| {
            seen.push(*index);
            *value += 10;
            index % 2 == 0
        });
        assert_eq!(seen, (0..9).collect::<Vec<_>>());
        assert_eq!(values.len(), 5);
        for index in 0..9 {
            assert_eq!(
                values.get(&index).map(|entry| *entry.1),
                (index % 2 == 0).then_some(u64::from(index) + 10)
            );
        }
    }

    #[test]
    fn interrupted_retain_does_not_reindex_the_unvisited_suffix() {
        let mut values = dense(8);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            values.retain(|index, _| {
                assert_ne!(*index, 3, "deliberate predicate panic");
                *index != 1
            });
        }));
        assert!(outcome.is_err());
        assert!(matches!(values, IndexedValues::Holey(_)));
        assert_eq!(values.get(&1), None);
        for index in [0, 2, 3, 4, 5, 6, 7] {
            assert_eq!(values.get(&index).map(|entry| *entry.1), Some(u64::from(index)));
        }
    }

    #[test]
    fn promotion_moves_non_clone_values_and_drops_each_once() {
        struct DropProbe(Rc<Cell<usize>>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let dropped = Rc::new(Cell::new(0));
        let mut values = IndexedValues::new();
        for index in 0..32 {
            values.insert(index, (index.to_string(), DropProbe(Rc::clone(&dropped))));
        }
        values.promote();
        assert_eq!(dropped.get(), 0, "promotion must move, not drop, values");
        drop(values.remove(&7));
        assert_eq!(dropped.get(), 1);
        values.clear();
        assert_eq!(dropped.get(), 32);
    }

    #[test]
    fn replacement_keeps_existing_key_backing_in_both_forms() {
        for dictionary in [false, true] {
            let mut values = dense(3);
            if dictionary {
                values.promote();
            }
            let pointer = values.get(&1).unwrap().0.as_ptr();
            assert_eq!(values.insert(1, ("1".to_string(), 99)), Some(1));
            assert_eq!(values.get(&1).unwrap().0.as_ptr(), pointer);
        }
    }

    #[test]
    fn guarded_dense_moves_keep_the_live_parent_carrier_queued() {
        use super::super::OrderedStringMap;

        let mut expected: Vec<i64> = (0..32).collect();
        let mut map: OrderedStringMap<i64> = expected
            .iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), *value))
            .collect();
        assert_eq!(map.shift_dense_index_values(32), Some(expected.remove(0)));
        assert!(matches!(map.array_entries, IndexedValues::Queue(_)));
        map.unshift_dense_index_values(31, vec![91, 92]).unwrap();
        drop(expected.splice(0..0, [91, 92]));
        assert!(matches!(map.array_entries, IndexedValues::Queue(_)));
        let removed: Vec<_> = expected.splice(2..7, [99]).collect();
        assert_eq!(map.splice_dense_index_values(33, 2, 5, vec![99]), Ok(removed));
        assert!(matches!(map.array_entries, IndexedValues::Queue(_)));
        assert_eq!(map.index_values().copied().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn deterministic_operation_stream_matches_btree_oracle() {
        // Exercise dense growth separately for each seed before sparse churn;
        // otherwise the first random gap would only test the fallback.
        for seed in 0..64_u64 {
            let mut values = IndexedValues::new();
            let mut oracle = BTreeMap::new();
            let mut random = seed + 1;
            for step in 0..1024_u32 {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                let index = if step < 128 {
                    step
                } else {
                    (random >> 32) as u32 % 256
                };
                match if step < 128 { 0 } else { random as u32 % 7 } {
                    0..=2 => {
                        let entry = (index.to_string(), random);
                        let expected = oracle
                            .insert(index, entry.clone())
                            .map(|(_, value)| value);
                        assert_eq!(values.insert(index, entry), expected);
                    }
                    3 => assert_eq!(values.remove(&index), oracle.remove(&index)),
                    4 => {
                        if let Some((_, value)) = values.get_mut(&index) {
                            *value ^= random;
                        }
                        if let Some((_, value)) = oracle.get_mut(&index) {
                            *value ^= random;
                        }
                    }
                    5 => {
                        values.retain(|key, (_, value)| {
                            *value = value.wrapping_add(1);
                            key % 11 != index % 11
                        });
                        oracle.retain(|key, (_, value)| {
                            *value = value.wrapping_add(1);
                            key % 11 != index % 11
                        });
                    }
                    _ => assert_eq!(values.get(&index), oracle.get(&index).map(|(key, value)| (key, value))),
                }
                assert_eq!(values.len(), oracle.len(), "seed={seed}, step={step}");
                assert_eq!(
                    values.values().collect::<Vec<_>>(),
                    oracle.values().map(|(key, value)| (key, value)).collect::<Vec<_>>()
                );
                assert_eq!(values.contains_key(&index), oracle.contains_key(&index));
                assert_eq!(values.get(&u32::MAX), None);
            }
        }
    }

    #[test]
    fn retain_all_keeps_the_packed_allocation_and_tail_rejection_stays_packed() {
        let mut values = dense(4096);
        let (address, capacity) = match &values {
            IndexedValues::Packed(entries) => (entries.as_ptr(), entries.capacity()),
            IndexedValues::Queue(_) | IndexedValues::Holey(_) | IndexedValues::Dictionary(_) => unreachable!(),
        };
        let key_addresses: Vec<_> = values.values().map(|entry| entry.0.as_ptr()).collect();
        let mut next = 0_u32;
        values.retain(|index, (_, value)| {
            assert_eq!(*index, next);
            next += 1;
            *value += 7;
            true
        });
        assert_eq!(next, 4096);
        let IndexedValues::Packed(entries) = &values else {
            panic!("all-keep retain must not build a dictionary");
        };
        assert_eq!((entries.as_ptr(), entries.capacity()), (address, capacity));
        for (index, (key, value)) in entries.iter().enumerate() {
            assert_eq!(*value, index as u64 + 7);
            assert_eq!(key.as_ptr(), key_addresses[index]);
        }
        values.retain(|index, _| *index != 4095);
        assert_eq!(values.len(), 4095);
        assert!(matches!(values, IndexedValues::Packed(_)));
        assert_eq!(values.get(&4094).map(|entry| *entry.1), Some(4101));
    }

    #[test]
    fn successful_prefix_filters_recover_packing_without_erasing_sparse_keys() {
        for dictionary in [false, true] {
            for kept in [0_u32, 1, 7, 32] {
                let mut values = dense(32);
                if dictionary {
                    values.promote();
                }
                values.retain(|index, _| *index < kept);
                let IndexedValues::Packed(entries) = &values else {
                    panic!("a successful prefix filter should recover packed storage");
                };
                assert_eq!(entries.len(), kept as usize);
                if kept == 0 {
                    assert_eq!(entries.capacity(), 0);
                }
                for index in kept..64 {
                    values.insert(index, (index.to_string(), u64::from(index)));
                }
                assert!(matches!(values, IndexedValues::Packed(_)));
                assert_eq!(values, dense(64));
            }
        }
        let mut sparse = dense(8);
        sparse.insert(u32::MAX - 1, ((u32::MAX - 1).to_string(), 99));
        sparse.retain(|index, _| *index != 1);
        assert!(matches!(sparse, IndexedValues::Dictionary(_)));
        assert_eq!(sparse.get(&1), None);
        assert_eq!(sparse.get(&2).map(|entry| *entry.1), Some(2));
        assert_eq!(sparse.get(&(u32::MAX - 1)).map(|entry| *entry.1), Some(99));
        sparse.insert(1, ("1".into(), 1));
        assert!(matches!(sparse, IndexedValues::Dictionary(_)), "insertion must not repack");
        sparse.retain(|index, _| *index < 8);
        assert!(matches!(sparse, IndexedValues::Packed(_)));
        assert_eq!(sparse, dense(8));
    }

    #[test]
    fn retain_partial_states_and_callbacks_match_btree_at_every_panic_boundary() {
        for len in 0..=6_u32 {
            for mask in 0..(1_u32 << len) {
                // len means no panic. Mutate BEFORE the panic so the current
                // entry, as well as every previously visited entry, is checked.
                for panic_at in 0..=len {
                    for dictionary in [false, true] {
                        let mut actual = dense(len);
                        if dictionary {
                            actual.promote();
                        }
                        let mut expected: BTreeMap<_, _> = (0..len)
                            .map(|index| (index, (index.to_string(), u64::from(index))))
                            .collect();
                        let mut actual_visits = Vec::new();
                        let mut expected_visits = Vec::new();
                        let actual_result = catch_unwind(AssertUnwindSafe(|| {
                            actual.retain(|index, (key, value)| {
                                actual_visits.push(*index);
                                key.push('!');
                                *value += 100;
                                assert_ne!(*index, panic_at, "deliberate predicate panic");
                                mask & (1 << *index) != 0
                            });
                        }));
                        let expected_result = catch_unwind(AssertUnwindSafe(|| {
                            expected.retain(|index, (key, value)| {
                                expected_visits.push(*index);
                                key.push('!');
                                *value += 100;
                                assert_ne!(*index, panic_at, "deliberate predicate panic");
                                mask & (1 << *index) != 0
                            });
                        }));
                        assert_eq!(actual_result.is_err(), expected_result.is_err());
                        assert_eq!(actual_visits, expected_visits);
                        assert_eq!(actual.len(), expected.len());
                        for index in 0..=len {
                            assert_eq!(actual.get(&index), expected.get(&index).map(|(key, value)| (key, value)),
                                "len={len} mask={mask} panic_at={panic_at} dictionary={dictionary}");
                        }
                        assert_eq!(actual.values().collect::<Vec<_>>(), expected.values().map(|(key, value)| (key, value)).collect::<Vec<_>>());
                        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                    }
                }
            }
        }
    }

    #[test]
    fn retain_recovery_moves_non_clone_values_and_drops_only_rejections() {
        struct Owned {
            bytes: Box<[u8; 16]>,
            dropped: Rc<Cell<usize>>,
        }
        impl Drop for Owned {
            fn drop(&mut self) {
                self.dropped.set(self.dropped.get() + 1);
            }
        }
        for dictionary in [false, true] {
            let dropped = Rc::new(Cell::new(0));
            let mut values = IndexedValues::new();
            for index in 0..16_u32 {
                values.insert(index, (index.to_string(), Owned {
                    bytes: Box::new([index as u8; 16]),
                    dropped: Rc::clone(&dropped),
                }));
            }
            let addresses: Vec<_> = values.values()
                .map(|(key, value)| (key.as_ptr(), value.bytes.as_ptr())).collect();
            if dictionary {
                values.promote();
            }
            values.retain(|index, (_, value)| {
                value.bytes[0] += 32;
                *index < 7
            });
            assert!(matches!(values, IndexedValues::Packed(_)));
            assert_eq!(dropped.get(), 9);
            for index in 0..7_u32 {
                let (key, value) = values.get(&index).unwrap();
                assert_eq!((key.as_ptr(), value.bytes.as_ptr()), addresses[index as usize]);
                assert_eq!(value.bytes[0], index as u8 + 32);
            }
            values.clear();
            assert_eq!(dropped.get(), 16);
        }
    }

    #[test]
    fn retain_drop_panic_leaves_the_same_numeric_suffix_as_btree() {
        use std::cell::RefCell;

        struct DropPanic {
            index: u32,
            panic_at: u32,
            drops: Rc<RefCell<Vec<u32>>>,
        }
        impl Drop for DropPanic {
            fn drop(&mut self) {
                self.drops.borrow_mut().push(self.index);
                assert_ne!(self.index, self.panic_at, "deliberate destructor panic");
            }
        }
        for panic_at in [0_u32, 3, 7] {
            let actual_drops = Rc::new(RefCell::new(Vec::new()));
            let expected_drops = Rc::new(RefCell::new(Vec::new()));
            let mut actual = IndexedValues::new();
            let mut expected = BTreeMap::new();
            for index in 0..8_u32 {
                actual.insert(index, (index.to_string(), DropPanic {
                    index, panic_at, drops: Rc::clone(&actual_drops),
                }));
                expected.insert(index, (index.to_string(), DropPanic {
                    index, panic_at, drops: Rc::clone(&expected_drops),
                }));
            }
            let mut actual_visits = Vec::new();
            let mut expected_visits = Vec::new();
            assert!(catch_unwind(AssertUnwindSafe(|| {
                actual.retain(|index, _| {
                    actual_visits.push(*index);
                    *index < panic_at
                });
            })).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| {
                expected.retain(|index, _| {
                    expected_visits.push(*index);
                    *index < panic_at
                });
            })).is_err());
            assert_eq!(actual_visits, expected_visits);
            assert_eq!(*actual_drops.borrow(), *expected_drops.borrow());
            assert_eq!(actual.values().map(|(_, value)| value.index).collect::<Vec<_>>(),
                expected.values().map(|(_, value)| value.index).collect::<Vec<_>>());
            assert!(!actual.contains_key(&panic_at));
            // The panicking value is already removed, so ordinary destruction
            // of the survivors must neither re-panic nor double-drop it.
            drop(actual);
            drop(expected);
            assert_eq!(*actual_drops.borrow(), *expected_drops.borrow());
            assert_eq!(actual_drops.borrow().len(), 8);
        }
    }

    #[test]
    fn retained_parent_carrier_keeps_exact_order_wire_and_dense_moves() {
        use super::super::{OrderedStringMap, canonical_array_index};
        use crate::js_string::JsString;

        let lone = JsString::from_code_units(&[0xD800]);
        let mut map = OrderedStringMap::new();
        map.insert("z".into(), 90_i64);
        map.insert_exact(lone.clone(), 99);
        map.insert("a".into(), 91);
        for index in 0..32 {
            map.insert(index.to_string(), i64::from(index));
        }
        let original_wire = serde_json::to_string(&map).unwrap();
        map.retain(|_, _| true);
        assert!(matches!(map.array_entries, IndexedValues::Packed(_)));
        assert_eq!(serde_json::to_string(&map).unwrap(), original_wire);
        map.retain(|key, _| canonical_array_index(key).is_none_or(|index| index < 8));
        assert!(matches!(map.array_entries, IndexedValues::Packed(_)));
        assert_eq!(map.exact_len(), 11);
        assert_eq!(map.get_exact(&lone), Some(&99));
        assert_eq!(map.shift_dense_index_values(8), Some(0));
        map.unshift_dense_index_values(7, vec![40, 41]).unwrap();
        assert_eq!(map.splice_dense_index_values(9, 2, 3, vec![50]), Ok(vec![1, 2, 3]));
        assert!(matches!(map.array_entries, IndexedValues::Queue(_)));
        assert_eq!(map.index_values().copied().collect::<Vec<_>>(), [40, 41, 50, 4, 5, 6, 7]);
        let wire = serde_json::to_string(&map).unwrap();
        let decoded: OrderedStringMap<i64> = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded, map);
        assert_eq!(serde_json::to_string(&decoded).unwrap(), wire);
        let names: Vec<_> = map.exact_keys().into_iter()
            .filter(|key| key.as_str().and_then(canonical_array_index).is_none()).collect();
        assert_eq!(names, [JsString::from("z"), lone, JsString::from("a")]);
    }

    #[test]
    fn retain_interior_rejections_keep_direct_storage_and_key_allocations() {
        for len in [8_u32, 63, 4096] {
            for rejected in [0, len / 2, len - 2] {
                let mut values = dense(len);
                let addresses: Vec<_> = values.values().map(|entry| entry.0.as_ptr()).collect();
                let mut visits = Vec::new();
                values.retain(|index, (_, value)| {
                    visits.push(*index);
                    *value += 100;
                    *index != rejected
                });
                assert_eq!(visits, (0..len).collect::<Vec<_>>());
                let IndexedValues::Holey(entries) = &values else {
                    panic!("one interior rejection must not build a dictionary");
                };
                assert_eq!(entries.live, len as usize - 1);
                assert_eq!(entries.slots.len(), len as usize);
                assert!(entries.slots.capacity() <= 2 * entries.live);
                for index in 0..len {
                    if index == rejected {
                        assert!(values.get(&index).is_none());
                    } else {
                        let (key, value) = values.get(&index).unwrap();
                        assert_eq!(key.as_ptr(), addresses[index as usize]);
                        assert_eq!(*value, u64::from(index) + 100);
                    }
                }
                // Repair/deletion cycles must not repeatedly migrate storage.
                let slots = entries.slots.as_ptr();
                for _ in 0..8 {
                    values.insert(rejected, (rejected.to_string(), 1));
                    values.retain(|index, _| *index != rejected);
                    let IndexedValues::Holey(entries) = &values else {
                        panic!("retain must preserve economical holey storage");
                    };
                    assert_eq!(entries.slots.as_ptr(), slots);
                }
            }
        }
    }

    #[test]
    fn retain_migrates_only_when_live_occupancy_requires_it() {
        for rejected_prefix in [1_u32, 63, 64, 65, 127, 128] {
            let mut values = dense(128);
            let mut visits = Vec::new();
            values.retain(|index, (_, value)| {
                visits.push(*index);
                *value += 1;
                *index >= rejected_prefix
            });
            assert_eq!(visits, (0..128).collect::<Vec<_>>());
            assert_eq!(values.len(), (128 - rejected_prefix) as usize);
            match &values {
                IndexedValues::Holey(entries) => {
                    assert!(rejected_prefix <= 64);
                    assert!(entries.is_bounded());
                    assert!(entries.slots.capacity() <= 2 * entries.live);
                }
                IndexedValues::Dictionary(_) => assert!((65..128).contains(&rejected_prefix)),
                IndexedValues::Packed(entries) => {
                    assert_eq!(rejected_prefix, 128);
                    assert_eq!(entries.capacity(), 0);
                }
                IndexedValues::Queue(_) => unreachable!("retain uses ordinary indexed storage"),
            }
            for index in 0..128 {
                assert_eq!(
                    values.get(&index).map(|entry| *entry.1),
                    (index >= rejected_prefix).then_some(u64::from(index) + 1)
                );
            }
        }
    }

    #[test]
    fn retain_drop_panics_match_btree_before_and_after_sparse_migration() {
        use std::cell::RefCell;

        struct Owned {
            index: u32,
            panic_at: u32,
            drops: Rc<RefCell<Vec<u32>>>,
        }
        impl Drop for Owned {
            fn drop(&mut self) {
                self.drops.borrow_mut().push(self.index);
                assert_ne!(self.index, self.panic_at, "deliberate destructor panic");
            }
        }
        for panic_at in [1_u32, 31, 42, 43, 63] {
            let actual_drops = Rc::new(RefCell::new(Vec::new()));
            let expected_drops = Rc::new(RefCell::new(Vec::new()));
            let mut actual = IndexedValues::new();
            let mut expected = BTreeMap::new();
            for index in 0..64_u32 {
                actual.insert(index, (index.to_string(), Owned {
                    index, panic_at, drops: Rc::clone(&actual_drops),
                }));
                expected.insert(index, (index.to_string(), Owned {
                    index, panic_at, drops: Rc::clone(&expected_drops),
                }));
            }
            let mut actual_visits = Vec::new();
            let mut expected_visits = Vec::new();
            assert!(catch_unwind(AssertUnwindSafe(|| {
                actual.retain(|index, _| {
                    actual_visits.push(*index);
                    index % 4 == 0
                });
            })).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| {
                expected.retain(|index, _| {
                    expected_visits.push(*index);
                    index % 4 == 0
                });
            })).is_err());
            assert_eq!(actual_visits, expected_visits);
            assert_eq!(*actual_drops.borrow(), *expected_drops.borrow());
            assert_eq!(actual.len(), expected.len());
            for index in 0..64 {
                assert_eq!(actual.contains_key(&index), expected.contains_key(&index));
            }
            if panic_at < 43 {
                let IndexedValues::Holey(entries) = &actual else {
                    panic!("the partial map is still at least half occupied");
                };
                assert!(entries.is_bounded());
                assert!(entries.slots.capacity() <= 2 * entries.live);
            } else {
                assert!(matches!(actual, IndexedValues::Dictionary(_)));
            }
            drop(actual);
            drop(expected);
            assert_eq!(*actual_drops.borrow(), *expected_drops.borrow());
            assert_eq!(actual_drops.borrow().len(), 64);
        }
    }

    #[test]
    fn retained_holes_preserve_parent_exact_order_and_wire_bytes() {
        use super::super::{OrderedStringMap, canonical_array_index};
        use crate::js_string::JsString;

        let mut actual = OrderedStringMap::new();
        let lone = JsString::from_code_units(&[0xd800]);
        actual.insert("z".into(), 900_i64);
        actual.insert_exact(lone.clone(), 901);
        actual.insert("a".into(), 902);
        for index in 0..128 {
            actual.insert(index.to_string(), i64::from(index));
        }
        let mut expected = actual.clone();
        expected.array_entries.promote();
        for map in [&mut actual, &mut expected] {
            map.retain(|key, value| {
                *value += 10;
                canonical_array_index(key).is_none_or(|index| index % 2 == 0)
            });
        }
        assert!(matches!(actual.array_entries, IndexedValues::Holey(_)));
        assert_eq!(actual, expected);
        assert_eq!(actual.exact_keys(), expected.exact_keys());
        // The String-key retain API does not visit exact-only sidecar keys.
        assert_eq!(actual.get_exact(&lone), Some(&901));
        assert_eq!(
            serde_json::to_string(&actual).unwrap(),
            serde_json::to_string(&expected).unwrap()
        );
        let wire = serde_json::to_string(&actual).unwrap();
        let decoded: OrderedStringMap<i64> = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded, actual);
    }
}

#[cfg(test)]
mod capacity_tests;
