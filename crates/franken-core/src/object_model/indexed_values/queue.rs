//! Dense queue storage separates logical index keys from movable values.
//!
//! The keys always name 0..len. A front removal discards the last key and the
//! first value, so every surviving String allocation keeps its numeric index.
//! Only guarded dense moves select this representation; property deletion is
//! still a hole, and converts back to the ordinary indexed carrier.

use super::{IndexedValues, shrink_target};
use std::collections::VecDeque;

#[derive(Clone)]
pub(crate) struct QueueValues<V> {
    pub(super) keys: Vec<String>,
    pub(super) values: VecDeque<V>,
}

impl<V> QueueValues<V> {
    pub(super) fn len(&self) -> usize {
        debug_assert_eq!(self.keys.len(), self.values.len());
        self.keys.len()
    }

    pub(super) fn shrink_spare_capacity(&mut self) {
        let live = self.len();
        if live == 0 {
            self.keys = Vec::new();
            self.values = VecDeque::new();
            return;
        }
        let target = shrink_target(live, live);
        // Keep the same geometric bound as packed storage. A discarded
        // prefix owns no V, and old high-water allocations are released as
        // the caller releases each removed entry's memory charge.
        if live < self.keys.capacity() / 2 {
            self.keys.shrink_to(target);
            if live < self.keys.capacity() / 2 {
                self.keys.shrink_to_fit();
            }
        }
        if std::mem::size_of::<V>() != 0 && live < self.values.capacity() / 2 {
            self.values.shrink_to(target);
            if live < self.values.capacity() / 2 {
                self.values.shrink_to_fit();
            }
        }
    }
}

impl<V> IndexedValues<V> {
    /// Prepare a dense queue without cloning values or renumbering keys.
    /// Reserve both buffers before moving ownership. An allocation refusal
    /// leaves the original carrier untouched for the existing dense fallback.
    fn prepare_queue(&mut self) -> bool {
        if matches!(self, Self::Queue(_)) {
            return true;
        }
        let len = self.len();
        let mut keys = Vec::new();
        let mut values = VecDeque::new();
        if keys.try_reserve_exact(len).is_err() || values.try_reserve_exact(len).is_err() {
            return false;
        }
        for (key, value) in std::mem::replace(self, Self::new()).into_values() {
            keys.push(key);
            values.push_back(value);
        }
        *self = Self::Queue(Box::new(QueueValues { keys, values }));
        true
    }

    /// Guarded dense shift. The first call moves the representation once;
    /// subsequent calls remove only one key and one value, with geometric
    /// capacity reduction amortized over the drain.
    pub(in crate::object_model) fn shift_dense(&mut self, len: u32) -> Option<V> {
        if len == 0 || !self.is_dense_prefix(len) {
            return None;
        }
        if len == 1 {
            return self.remove(&0).map(|(_, value)| value);
        }
        if self.prepare_queue() {
            let Self::Queue(entries) = self else {
                unreachable!()
            };
            let removed = entries.values.pop_front();
            entries.keys.pop();
            entries.shrink_spare_capacity();
            if entries.len() == 0 {
                self.clear();
            }
            return removed;
        }
        // Optional storage conversion failed: retain the existing exact
        // algorithm. No partial movement or semantic refusal was introduced.
        let mut values = self.values_mut().map(|(_, value)| value);
        let mut previous = values.next()?;
        for current in values {
            std::mem::swap(previous, current);
            previous = current;
        }
        self.remove(&(len - 1)).map(|(_, value)| value)
    }

    /// Guarded dense unshift. Existing values and key allocations remain in
    /// place; only the added values and new highest index keys are inserted.
    pub(in crate::object_model) fn unshift_dense(
        &mut self,
        len: u32,
        items: Vec<V>,
    ) -> Result<(), Vec<V>> {
        let Some(new_len) = u32::try_from(items.len())
            .ok()
            .and_then(|n| len.checked_add(n))
        else {
            return Err(items);
        };
        if !self.is_dense_prefix(len) {
            return Err(items);
        }
        if items.is_empty() {
            return Ok(());
        }
        if self.prepare_queue() {
            let Self::Queue(entries) = self else {
                unreachable!()
            };
            // Reserve before appending keys so a caught allocation panic
            // cannot leave the two carriers at different lengths.
            entries.keys.reserve(items.len());
            entries.values.reserve(items.len());
            for index in len..new_len {
                entries.keys.push(index.to_string());
            }
            for item in items.into_iter().rev() {
                entries.values.push_front(item);
            }
            return Ok(());
        }
        let count = items.len();
        for (index, item) in (len..new_len).zip(items) {
            self.insert(index, (index.to_string(), item));
        }
        let mut values: Vec<&mut V> = self.values_mut().map(|(_, value)| value).collect();
        super::super::reverse_values(&mut values);
        let (front, back) = values.split_at_mut(count);
        super::super::reverse_values(front);
        super::super::reverse_values(back);
        Ok(())
    }

    /// Optional queue path for a length-changing dense prefix splice.
    /// Only removed and inserted values move after the one-time conversion;
    /// surviving values keep their ring slots and keys keep their indices.
    /// A refusal returns the items with the logical map unchanged so the
    /// caller can use the existing generic dense splice algorithm.
    pub(in crate::object_model) fn splice_dense_prefix(
        &mut self,
        len: u32,
        delete_count: u32,
        items: Vec<V>,
    ) -> Result<Vec<V>, Vec<V>> {
        let Some(new_len) = len.checked_sub(delete_count).and_then(|remaining| {
            u32::try_from(items.len())
                .ok()
                .and_then(|count| remaining.checked_add(count))
        }) else {
            return Err(items);
        };
        if new_len == len || !self.is_dense_prefix(len) {
            return Err(items);
        }

        // Prepare every fallible buffer and key before taking a value out.
        // No destructor for V runs while the two queue lengths differ, and
        // a caught key-construction panic cannot leave partial numeric keys.
        let mut removed = Vec::new();
        if removed.try_reserve_exact(delete_count as usize).is_err() {
            return Err(items);
        }
        let growth = new_len.saturating_sub(len) as usize;
        let mut added_keys = Vec::new();
        if added_keys.try_reserve_exact(growth).is_err() {
            return Err(items);
        }
        added_keys.extend((len..new_len).map(|index| index.to_string()));
        if !self.prepare_queue() {
            return Err(items);
        }
        let Self::Queue(entries) = self else {
            unreachable!()
        };
        if entries.keys.try_reserve(growth).is_err() || entries.values.try_reserve(growth).is_err()
        {
            return Err(items);
        }

        // Reserving the final length above suffices: removal happens first.
        // Drain only the prefix, leaving the surviving suffix in its slots.
        removed.extend(entries.values.drain(..delete_count as usize));
        for item in items.into_iter().rev() {
            entries.values.push_front(item);
        }
        if new_len < len {
            entries.keys.truncate(new_len as usize);
            entries.shrink_spare_capacity();
        } else {
            entries.keys.extend(added_keys);
        }
        if entries.len() == 0 {
            self.clear();
        }
        Ok(removed)
    }

    /// Operations that can expose holes retain their existing panic-safe
    /// packed/holey semantics. This linear conversion belongs to those
    /// already-linear operations, never to ordinary indexed reads or writes.
    pub(super) fn queue_to_packed(&mut self) {
        let Self::Queue(entries) = self else { return };
        let mut packed = Vec::with_capacity(entries.len());
        packed.extend(
            std::mem::take(&mut entries.keys)
                .into_iter()
                .zip(std::mem::take(&mut entries.values)),
        );
        *self = Self::Packed(packed);
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::OrderedStringMap;
    use super::*;
    use crate::js_string::JsString;
    use std::cell::{Cell, RefCell};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::rc::Rc;

    fn dense(len: u32) -> IndexedValues<u64> {
        let mut values = IndexedValues::new();
        for index in 0..len {
            values.insert(index, (index.to_string(), u64::from(index)));
        }
        values
    }

    fn check_queue_bounds<V>(values: &IndexedValues<V>) {
        match values {
            IndexedValues::Queue(entries) => {
                let live = entries.len();
                assert_ne!(live, 0, "empty queues release both backing allocations");
                let limit = (2 * live + 1).max(4);
                assert!(entries.keys.capacity() <= limit);
                if std::mem::size_of::<V>() != 0 {
                    assert!(entries.values.capacity() <= limit);
                }
            }
            IndexedValues::Packed(entries) => assert!(entries.is_empty()),
            _ => panic!("dense end mutations must not create holes or a dictionary"),
        }
    }

    #[test]
    fn front_moves_preserve_survivor_addresses_and_logical_key_allocations() {
        let mut values = dense(4096);
        assert_eq!(values.shift_dense(4096), Some(0));
        let key_address = values.get(&0).unwrap().0.as_ptr();
        let survivor_address = values.get(&3000).unwrap().1 as *const u64;
        // No shrink/growth threshold is crossed: a queue move must not
        // relocate the survivor, even as its logical index changes.
        for removed in 1..=1000_u32 {
            assert_eq!(values.shift_dense(4096 - removed), Some(u64::from(removed)));
            assert_eq!(
                values.get(&(3000 - removed)).unwrap().1 as *const u64,
                survivor_address
            );
            assert_eq!(values.get(&0).unwrap().0.as_ptr(), key_address);
            check_queue_bounds(&values);
        }
        for added in 0..1000_u32 {
            values
                .unshift_dense(3095 + added, vec![10_000 + u64::from(added)])
                .unwrap();
            assert_eq!(
                values.get(&(2001 + added)).unwrap().1 as *const u64,
                survivor_address
            );
            assert_eq!(values.get(&0).unwrap().0.as_ptr(), key_address);
            check_queue_bounds(&values);
        }
        for (index, (key, _)) in values.values().enumerate() {
            assert_eq!(key, &index.to_string());
        }
    }

    #[test]
    fn prefix_splices_preserve_survivor_slots_and_logical_key_allocations() {
        let mut actual = OrderedStringMap::new();
        actual.array_entries = dense(4096);
        assert_eq!(
            actual.splice_dense_index_values(4096, 0, 1, Vec::new()),
            Ok(vec![0])
        );
        let mut expected: Vec<_> = (1..4096_u64).collect();
        let key_address = actual.array_entries.get(&0).unwrap().0.as_ptr();
        let survivor_address = actual.get_index(3000).unwrap() as *const u64;
        // Both directions stay within the prepared queue's capacity and
        // above its shrink threshold. A prefix splice must not relocate a
        // surviving suffix even when it both removes and inserts values.
        for step in 0..1000_u32 {
            let items = vec![10_000 + u64::from(step)];
            let removed: Vec<_> = expected.splice(..2, items.clone()).collect();
            assert_eq!(
                actual.splice_dense_index_values(4095 - step, 0, 2, items),
                Ok(removed)
            );
            assert_eq!(
                actual.get_index(2999 - step).unwrap() as *const u64,
                survivor_address
            );
            assert_eq!(
                actual.array_entries.get(&0).unwrap().0.as_ptr(),
                key_address
            );
            check_queue_bounds(&actual.array_entries);
        }
        for step in 0..1000_u32 {
            let items = vec![20_000 + u64::from(step), 30_000 + u64::from(step)];
            let removed: Vec<_> = expected.splice(..1, items.clone()).collect();
            assert_eq!(
                actual.splice_dense_index_values(3095 + step, 0, 1, items),
                Ok(removed)
            );
            assert_eq!(
                actual.get_index(2001 + step).unwrap() as *const u64,
                survivor_address
            );
            assert_eq!(
                actual.array_entries.get(&0).unwrap().0.as_ptr(),
                key_address
            );
            check_queue_bounds(&actual.array_entries);
        }
        assert_eq!(actual.index_values().copied().collect::<Vec<_>>(), expected);
        for (index, (key, _)) in actual.array_entries.values().enumerate() {
            assert_eq!(key, &index.to_string());
        }
    }

    #[test]
    fn prefix_splices_match_vec_and_wire_from_every_dense_carrier() {
        let lone = JsString::from_code_units(&[0xd800]);
        for len in 0..8_u32 {
            for delete_count in 0..=len {
                for count in 0..5_u64 {
                    for carrier in 0..4 {
                        let mut actual = OrderedStringMap::new();
                        let mut model: Vec<_> =
                            (0..len).map(|n| (n != 1).then_some(u64::from(n))).collect();
                        for (index, value) in model.iter().enumerate() {
                            actual.insert(index.to_string(), *value);
                        }
                        actual.insert("tag".into(), Some(900));
                        actual.insert_exact(lone.clone(), Some(901));
                        match carrier {
                            0 => {}
                            1 if len != 0 => assert!(actual.array_entries.prepare_queue()),
                            2 => actual.array_entries.make_holey(),
                            3 => actual.array_entries.promote(),
                            _ => {}
                        }
                        let before_carrier = std::mem::discriminant(&actual.array_entries);
                        let items: Vec<_> = (0..count).map(|n| Some(100 + n)).collect();
                        let removed: Vec<_> = model
                            .splice(..delete_count as usize, items.clone())
                            .collect();
                        assert_eq!(
                            actual.splice_dense_index_values(len, 0, delete_count, items),
                            Ok(removed)
                        );
                        if count == u64::from(delete_count) {
                            assert_eq!(
                                std::mem::discriminant(&actual.array_entries),
                                before_carrier,
                                "equal-length replacement needs no representation conversion"
                            );
                        } else {
                            check_queue_bounds(&actual.array_entries);
                        }
                        let mut expected = OrderedStringMap::new();
                        for (index, value) in model.into_iter().enumerate() {
                            expected.insert(index.to_string(), value);
                        }
                        expected.insert("tag".into(), Some(900));
                        expected.insert_exact(lone.clone(), Some(901));
                        assert_eq!(actual, expected);
                        let wire = serde_json::to_string(&actual).unwrap();
                        assert_eq!(wire, serde_json::to_string(&expected).unwrap());
                        let restored: OrderedStringMap<Option<u64>> =
                            serde_json::from_str(&wire).unwrap();
                        assert_eq!(restored, actual);
                        assert_eq!(restored.exact_keys(), actual.exact_keys());
                    }
                }
            }
        }
    }

    #[test]
    fn prefix_splice_drain_keeps_geometric_headroom_and_releases_backings() {
        let mut actual = OrderedStringMap::new();
        actual.array_entries = dense(8192);
        let mut previous = (0, 0);
        let mut capacity_changes = 0;
        for len in (2..=8192_u32).rev() {
            assert_eq!(
                actual
                    .splice_dense_index_values(len, 0, 2, vec![u64::MAX])
                    .unwrap()
                    .len(),
                2
            );
            check_queue_bounds(&actual.array_entries);
            assert_eq!(actual.array_entries.len(), len as usize - 1);
            let IndexedValues::Queue(entries) = &actual.array_entries else {
                panic!("non-empty prefix splice should retain the queue")
            };
            let capacity = (entries.keys.capacity(), entries.values.capacity());
            if capacity != previous {
                capacity_changes += 1;
                previous = capacity;
            }
        }
        assert!(
            capacity_changes < 64,
            "{capacity_changes} resizes in a linear drain"
        );
        assert_eq!(
            actual.splice_dense_index_values(1, 0, 1, Vec::new()),
            Ok(vec![u64::MAX])
        );
        let IndexedValues::Packed(entries) = &actual.array_entries else {
            panic!("empty splice must release the queue")
        };
        assert_eq!(entries.capacity(), 0);
        check_queue_bounds(&actual.array_entries);
    }

    #[test]
    fn draining_and_end_churn_keep_geometric_headroom_and_release_backings() {
        let mut values = dense(8192);
        values.shift_dense(8192);
        let mut previous = (0, 0);
        let mut capacity_changes = 0;
        for len in (1..8192_u32).rev() {
            // The old exact-fit shrink path could resize on every
            // append/two-remove cycle. Include a front move in that stream.
            values.insert(len, (len.to_string(), 55));
            check_queue_bounds(&values);
            values.remove(&len);
            values.shift_dense(len);
            check_queue_bounds(&values);
            let capacity = match &values {
                IndexedValues::Queue(entries) => {
                    (entries.keys.capacity(), entries.values.capacity())
                }
                IndexedValues::Packed(entries) => (entries.capacity(), 0),
                _ => unreachable!(),
            };
            if capacity != previous {
                capacity_changes += 1;
                previous = capacity;
            }
        }
        assert!(
            capacity_changes < 64,
            "{capacity_changes} resizes in a linear drain"
        );
        assert!(values.is_empty());
        assert_eq!(previous, (0, 0));
        values.unshift_dense(0, vec![7, 8]).unwrap();
        assert_eq!(values.shift_dense(2), Some(7));
        assert_eq!(values.shift_dense(1), Some(8));
        check_queue_bounds(&values);
    }

    #[test]
    fn queue_ranges_and_bidirectional_iterators_preserve_numeric_order() {
        let mut values = dense(40);
        for len in (31..=40).rev() {
            values.shift_dense(len);
        }
        values.unshift_dense(30, vec![80, 81, 82]).unwrap();
        for (_, value) in values.range_values_mut(2..9) {
            *value += 100;
        }
        for (_, value) in values.values_mut().rev() {
            *value += 1;
        }
        let expected: Vec<_> = values.clone().into_values().collect();
        let mut oracle: Vec<_> = [80, 81, 82].into_iter().chain(10..40_u64).collect();
        for value in &mut oracle[2..9] {
            *value += 100;
        }
        for value in &mut oracle {
            *value += 1;
        }
        assert_eq!(
            expected.iter().map(|(_, value)| *value).collect::<Vec<_>>(),
            oracle
        );
        let mut iterator = values.values();
        let mut owned = values.clone().into_values();
        let mut first = 0;
        let mut last = expected.len();
        for step in 0..expected.len() {
            assert_eq!(iterator.len(), last - first);
            assert_eq!(owned.len(), last - first);
            let index = if step % 2 == 0 {
                let i = first;
                first += 1;
                i
            } else {
                last -= 1;
                last
            };
            let borrowed = if step % 2 == 0 {
                iterator.next()
            } else {
                iterator.next_back()
            };
            let taken = if step % 2 == 0 {
                owned.next()
            } else {
                owned.next_back()
            };
            assert_eq!(borrowed, Some((&expected[index].0, &expected[index].1)));
            assert_eq!(taken, Some(expected[index].clone()));
            assert_eq!(expected[index].0, index.to_string());
        }
        assert_eq!(iterator.next(), None);
        assert_eq!(iterator.next_back(), None);
        assert_eq!(owned.next(), None);
        assert_eq!(owned.next_back(), None);
        let mut dictionary = values.clone();
        dictionary.promote();
        assert_eq!(values, dictionary);
        assert_eq!(dictionary, values);
        assert_eq!(format!("{values:?}"), format!("{dictionary:?}"));
        for start in 0..36 {
            assert_eq!(
                values.range_values_mut(start..40).count(),
                33_usize.saturating_sub(start as usize)
            );
        }
    }

    #[test]
    fn queue_transitions_preserve_holes_exact_keys_wire_and_guard_refusals() {
        let lone = JsString::from_code_units(&[0xd800]);
        let mut actual = OrderedStringMap::new();
        actual.insert("z".into(), Some(900_u64));
        actual.insert_exact(lone.clone(), Some(901));
        actual.insert("a".into(), Some(902));
        for index in 0..128_u32 {
            actual.insert(index.to_string(), (index != 2).then_some(u64::from(index)));
        }
        assert_eq!(actual.shift_dense_index_values(128), Some(Some(0)));
        actual
            .unshift_dense_index_values(127, vec![Some(700), None])
            .unwrap();
        assert_eq!(
            actual.get_index(1),
            Some(&None),
            "present undefined is not a hole"
        );
        let queued = actual.clone();
        let original_wire = serde_json::to_string(&actual).unwrap();
        assert_eq!(actual.shift_dense_index_values(128), None);
        assert_eq!(
            actual.unshift_dense_index_values(128, vec![Some(777)]),
            Err(vec![Some(777)])
        );
        for (len, delete_count) in [(128, 1), (129, 130), (129, u32::MAX)] {
            assert_eq!(
                actual.splice_dense_index_values(len, 0, delete_count, vec![Some(777)]),
                Err(vec![Some(777)])
            );
        }
        assert_eq!(serde_json::to_string(&actual).unwrap(), original_wire);
        let mut expected = actual.clone();
        expected.array_entries.promote();
        for map in [&mut actual, &mut expected] {
            assert_eq!(map.remove("7"), Some(Some(6)));
            assert_eq!(map.get_index(7), None);
            assert_eq!(map.shift_dense_index_values(128), None);
            let holed_wire = serde_json::to_string(&map).unwrap();
            assert_eq!(
                map.splice_dense_index_values(128, 0, 2, vec![Some(888)]),
                Err(vec![Some(888)])
            );
            assert_eq!(serde_json::to_string(&map).unwrap(), holed_wire);
            map.insert("7".into(), Some(66));
            map.insert("131".into(), Some(131));
            map.insert("4294967294".into(), Some(99));
            map.retain(|key, _| key != "12");
        }
        assert_eq!(actual, expected);
        assert_eq!(actual.get_exact(&lone), Some(&Some(901)));
        assert_eq!(
            serde_json::to_string(&actual).unwrap(),
            serde_json::to_string(&expected).unwrap()
        );
        let wire = serde_json::to_string(&queued).unwrap();
        let restored: OrderedStringMap<Option<u64>> = serde_json::from_str(&wire).unwrap();
        assert_eq!(restored, queued);
        assert_eq!(serde_json::to_string(&restored).unwrap(), wire);
        assert_eq!(queued.exact_keys(), restored.exact_keys());
        assert_eq!(
            queued.into_iter().collect::<Vec<_>>(),
            restored.into_iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn queue_moves_non_clone_values_and_normalizes_before_drop_panics() {
        struct Owned {
            id: u32,
            drops: Rc<RefCell<Vec<u32>>>,
            panic_next: Rc<Cell<bool>>,
        }
        impl Drop for Owned {
            fn drop(&mut self) {
                self.drops.borrow_mut().push(self.id);
                assert!(
                    !self.panic_next.replace(false),
                    "deliberate returned-value drop panic"
                );
            }
        }
        let drops = Rc::new(RefCell::new(Vec::new()));
        let panic_next = Rc::new(Cell::new(false));
        let owned = |id| Owned {
            id,
            drops: Rc::clone(&drops),
            panic_next: Rc::clone(&panic_next),
        };
        let mut values = IndexedValues::new();
        for index in 0..32 {
            values.insert(index, (index.to_string(), owned(index)));
        }
        drop(values.shift_dense(32));
        assert_eq!(*drops.borrow(), [0]);
        assert!(values.unshift_dense(31, vec![owned(32), owned(33)]).is_ok());
        panic_next.set(true);
        assert!(catch_unwind(AssertUnwindSafe(|| drop(values.shift_dense(33)))).is_err());
        assert_eq!(values.len(), 32);
        assert_eq!(values.get(&0).unwrap().1.id, 33);
        assert_eq!(values.get(&1).unwrap().1.id, 1);
        check_queue_bounds(&values);
        // A removed vector can run arbitrary destructors only after all
        // splice movement, logical keys and capacity accounting are settled.
        let Ok(removed) = values.splice_dense_prefix(32, 3, vec![owned(34)]) else {
            panic!("dense shrinking prefix splice")
        };
        panic_next.set(true);
        assert!(catch_unwind(AssertUnwindSafe(|| drop(removed))).is_err());
        assert_eq!(values.len(), 30);
        assert_eq!(values.get(&0).unwrap().1.id, 34);
        assert_eq!(values.get(&1).unwrap().1.id, 3);
        check_queue_bounds(&values);
        let Ok(removed) = values.splice_dense_prefix(30, 1, vec![owned(35), owned(36), owned(37)])
        else {
            panic!("dense growing prefix splice")
        };
        assert_eq!(
            removed.iter().map(|value| value.id).collect::<Vec<_>>(),
            [34]
        );
        drop(removed);
        assert_eq!(values.len(), 32);
        assert_eq!(values.get(&0).unwrap().1.id, 35);
        assert_eq!(values.get(&3).unwrap().1.id, 3);
        check_queue_bounds(&values);
        // A true property deletion preserves later indices while converting
        // the ring into holey storage; no value may be cloned or lost.
        drop(values.remove(&7));
        assert!(values.get(&7).is_none());
        assert_eq!(values.get(&8).unwrap().1.id, 8);
        drop(values);
        let mut dropped = drops.borrow().clone();
        dropped.sort_unstable();
        assert_eq!(dropped, (0..38).collect::<Vec<_>>());
    }
}
