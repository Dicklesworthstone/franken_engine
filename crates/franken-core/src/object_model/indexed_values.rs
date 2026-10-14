//! Dense numeric properties for the shared baseline property carrier.
//!
//! This is storage, not Array semantics: lengths, descriptors, prototypes,
//! labels and resource admission remain with the existing callers. Dense
//! prefixes use direct indexing. A gap or interior deletion moves ownership
//! into the existing ordered dictionary; it never allocates up to a sparse
//! index. No Value is cloned, normalized, or replaced with an undefined hole.

use std::collections::{BTreeMap, btree_map};
use std::fmt;
use std::ops::Range;
use std::slice;
use std::vec;

#[derive(Clone)]
pub(super) enum IndexedValues<V> {
    Packed(Vec<(String, V)>),
    Dictionary(BTreeMap<u32, (String, V)>),
}

impl<V> IndexedValues<V> {
    pub(super) fn new() -> Self {
        Self::Packed(Vec::new())
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Packed(entries) => entries.len(),
            Self::Dictionary(entries) => entries.len(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub(super) fn get(&self, index: &u32) -> Option<&(String, V)> {
        match self {
            Self::Packed(entries) => entries.get(*index as usize),
            Self::Dictionary(entries) => entries.get(index),
        }
    }

    #[inline]
    pub(super) fn get_mut(&mut self, index: &u32) -> Option<&mut (String, V)> {
        match self {
            Self::Packed(entries) => entries.get_mut(*index as usize),
            Self::Dictionary(entries) => entries.get_mut(index),
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
                // A sparse write must not reserve index-sized native storage.
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
                    // Shrink geometrically rather than reallocating each pop.
                    if entries.is_empty() {
                        *entries = Vec::new();
                    } else if entries.len() < entries.capacity() / 2 {
                        entries.shrink_to_fit();
                    }
                    return removed;
                }
                self.promote();
                self.remove(index)
            }
            Self::Dictionary(entries) => entries.remove(index),
        }
    }

    pub(super) fn clear(&mut self) {
        *self = Self::new();
    }

    /// Promote before invoking user-supplied Rust predicates. If a predicate
    /// unwinds after removing an interior entry, the map must still have valid
    /// numeric keys; Vec::retain_mut alone would silently compact the indices.
    pub(super) fn retain(&mut self, keep: impl FnMut(&u32, &mut (String, V)) -> bool) {
        if self.is_empty() {
            return;
        }
        self.promote();
        if let Self::Dictionary(entries) = self {
            entries.retain(keep);
        }
    }

    /// The map contains exactly 0..len, independently of its storage form.
    pub(super) fn is_dense_prefix(&self, len: u32) -> bool {
        if self.len() != len as usize {
            return false;
        }
        match self {
            Self::Packed(_) => true,
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
            Self::Dictionary(entries) => Values::Dictionary(entries.values()),
        }
    }

    pub(super) fn values_mut(&mut self) -> ValuesMut<'_, V> {
        match self {
            Self::Packed(entries) => ValuesMut::Packed(entries.iter_mut()),
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
            Self::Dictionary(entries) => RangeValuesMut::Dictionary(entries.range_mut(range)),
        }
    }

    pub(super) fn into_values(self) -> IntoValues<V> {
        match self {
            Self::Packed(entries) => IntoValues::Packed(entries.into_iter()),
            Self::Dictionary(entries) => IntoValues::Dictionary(entries.into_values()),
        }
    }

    fn promote(&mut self) {
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
            (Self::Packed(left), Self::Packed(right)) => left == right,
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
            Self::Dictionary(entries) => fmt::Debug::fmt(entries, formatter),
        }
    }
}

pub(super) enum Values<'a, V> {
    Packed(slice::Iter<'a, (String, V)>),
    Dictionary(btree_map::Values<'a, u32, (String, V)>),
}

impl<'a, V> Iterator for Values<'a, V> {
    type Item = &'a (String, V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next(),
            Self::Dictionary(entries) => entries.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Packed(entries) => entries.size_hint(),
            Self::Dictionary(entries) => entries.size_hint(),
        }
    }
}

impl<V> DoubleEndedIterator for Values<'_, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next_back(),
            Self::Dictionary(entries) => entries.next_back(),
        }
    }
}

impl<V> ExactSizeIterator for Values<'_, V> {}
impl<V> std::iter::FusedIterator for Values<'_, V> {}

pub(super) enum ValuesMut<'a, V> {
    Packed(slice::IterMut<'a, (String, V)>),
    Dictionary(btree_map::ValuesMut<'a, u32, (String, V)>),
}

impl<'a, V> Iterator for ValuesMut<'a, V> {
    type Item = &'a mut (String, V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next(),
            Self::Dictionary(entries) => entries.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Packed(entries) => entries.size_hint(),
            Self::Dictionary(entries) => entries.size_hint(),
        }
    }
}

impl<V> DoubleEndedIterator for ValuesMut<'_, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next_back(),
            Self::Dictionary(entries) => entries.next_back(),
        }
    }
}

impl<V> ExactSizeIterator for ValuesMut<'_, V> {}
impl<V> std::iter::FusedIterator for ValuesMut<'_, V> {}

pub(super) enum RangeValuesMut<'a, V> {
    Packed(slice::IterMut<'a, (String, V)>),
    Dictionary(btree_map::RangeMut<'a, u32, (String, V)>),
}

impl<'a, V> Iterator for RangeValuesMut<'a, V> {
    type Item = &'a mut (String, V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next(),
            Self::Dictionary(entries) => entries.next().map(|(_, entry)| entry),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Packed(entries) => entries.size_hint(),
            Self::Dictionary(entries) => entries.size_hint(),
        }
    }
}

impl<V> DoubleEndedIterator for RangeValuesMut<'_, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next_back(),
            Self::Dictionary(entries) => entries.next_back().map(|(_, entry)| entry),
        }
    }
}

impl<V> std::iter::FusedIterator for RangeValuesMut<'_, V> {}

pub(super) enum IntoValues<V> {
    Packed(vec::IntoIter<(String, V)>),
    Dictionary(btree_map::IntoValues<u32, (String, V)>),
}

impl<V> Iterator for IntoValues<V> {
    type Item = (String, V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next(),
            Self::Dictionary(entries) => entries.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Packed(entries) => entries.size_hint(),
            Self::Dictionary(entries) => entries.size_hint(),
        }
    }
}

impl<V> DoubleEndedIterator for IntoValues<V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packed(entries) => entries.next_back(),
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
            assert_eq!(values.get(&index).map(|entry| entry.1), Some(u64::from(index)));
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
        assert!(matches!(values, IndexedValues::Dictionary(_)));
        assert_eq!(values.get(&1), None);
        assert_eq!(values.get(&2).map(|entry| entry.1), Some(2));
        assert!(!values.is_dense_prefix(4));
        values.insert(1, ("1".into(), 1));
        assert!(values.is_dense_prefix(5));
        // Repairing a hole does not repeatedly migrate the representation.
        assert!(matches!(values, IndexedValues::Dictionary(_)));
        values.insert(u32::MAX - 1, ((u32::MAX - 1).to_string(), 88));
        assert_eq!(values.len(), 6);
        assert_eq!(values.get(&(u32::MAX - 1)).map(|entry| entry.1), Some(88));
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
                dictionary.get_mut(&0).unwrap().1 = 99;
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
                values.get(&index).map(|entry| entry.1),
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
        assert!(matches!(values, IndexedValues::Dictionary(_)));
        assert_eq!(values.get(&1), None);
        for index in [0, 2, 3, 4, 5, 6, 7] {
            assert_eq!(values.get(&index).map(|entry| entry.1), Some(u64::from(index)));
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
    fn guarded_dense_moves_keep_the_live_parent_carrier_packed() {
        use super::super::OrderedStringMap;

        let mut expected: Vec<i64> = (0..32).collect();
        let mut map: OrderedStringMap<i64> = expected
            .iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), *value))
            .collect();
        assert_eq!(map.shift_dense_index_values(32), Some(expected.remove(0)));
        assert!(matches!(map.array_entries, IndexedValues::Packed(_)));
        map.unshift_dense_index_values(31, vec![91, 92]).unwrap();
        drop(expected.splice(0..0, [91, 92]));
        assert!(matches!(map.array_entries, IndexedValues::Packed(_)));
        let removed: Vec<_> = expected.splice(2..7, [99]).collect();
        assert_eq!(map.splice_dense_index_values(33, 2, 5, vec![99]), Ok(removed));
        assert!(matches!(map.array_entries, IndexedValues::Packed(_)));
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
                    _ => assert_eq!(values.get(&index), oracle.get(&index)),
                }
                assert_eq!(values.len(), oracle.len(), "seed={seed}, step={step}");
                assert_eq!(
                    values.values().collect::<Vec<_>>(),
                    oracle.values().collect::<Vec<_>>()
                );
                assert_eq!(values.contains_key(&index), oracle.contains_key(&index));
                assert_eq!(values.get(&u32::MAX), None);
            }
        }
    }
}