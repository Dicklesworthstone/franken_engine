use super::*;
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn dense(length: u32) -> IndexedValues<u64> {
    let mut values = IndexedValues::new();
    for index in 0..length {
        values.insert(index, (index.to_string(), u64::from(index)));
    }
    values
}

fn check_bounds<V>(values: &IndexedValues<V>) {
    if let IndexedValues::Holey(entries) = values {
        assert!(entries.live > 0);
        assert_eq!(entries.live, entries.slots.iter().flatten().count());
        assert!(entries.slots.last().unwrap().is_some());
        assert!(entries.is_bounded());
        assert!(entries.slots.capacity() <= entries.live * 2);
    }
}

#[test]
fn deletion_and_repair_keep_slots_and_untouched_key_allocations() {
    let mut values = dense(4096);
    let key_pointer = values.get(&4095).unwrap().0.as_ptr();
    assert_eq!(values.remove(&17), Some(("17".into(), 17)));
    let IndexedValues::Holey(entries) = &values else { panic!("use holey slots"); };
    let slots = entries.slots.as_ptr();
    for cycle in 0..4096 {
        assert_eq!(values.get(&17), None);
        assert_eq!(values.get(&4095).unwrap().0.as_ptr(), key_pointer);
        assert_eq!(values.insert(17, ("17".into(), cycle)), None);
        assert!(values.is_dense_prefix(4096));
        assert_eq!(values.remove(&17), Some(("17".into(), cycle)));
        let IndexedValues::Holey(entries) = &values else { panic!("no churn migration"); };
        assert_eq!(entries.slots.as_ptr(), slots);
        check_bounds(&values);
    }
    // A repaired hole can participate in the parent's guarded dense moves.
    values.insert(17, ("17".into(), 17));
    values.retain(|_, _| true);
    assert!(matches!(values, IndexedValues::Packed(_)));
    assert_eq!(values, dense(4096));
}

#[test]
fn deletion_density_tail_release_and_remote_indices_are_bounded() {
    let mut values = dense(128);
    for index in 0..64 {
        values.remove(&index);
        check_bounds(&values);
        assert!(matches!(values, IndexedValues::Holey(_)));
    }
    values.remove(&64);
    assert!(matches!(values, IndexedValues::Dictionary(_)));
    assert_eq!(*values.get(&127).unwrap().1, 127);
    values.insert(u32::MAX - 1, ((u32::MAX - 1).to_string(), 7));
    assert_eq!(values.len(), 64);
    assert!(matches!(values, IndexedValues::Dictionary(_)));

    let mut tail = dense(128);
    tail.remove(&7);
    for index in (8..128).rev() {
        tail.remove(&index);
        check_bounds(&tail);
    }
    assert_eq!(tail.len(), 7);
    for index in (0..7).rev() { tail.remove(&index); }
    let IndexedValues::Packed(entries) = tail else { panic!("empty storage released"); };
    assert_eq!(entries.capacity(), 0);
}

#[test]
fn regrowth_does_not_resize_every_append_or_retain_excess_capacity() {
    let mut values = dense(128);
    values.remove(&1);
    let mut reallocations = 0;
    let mut previous = 0;
    for index in 128..4096 {
        values.insert(index, (index.to_string(), u64::from(index)));
        let IndexedValues::Holey(entries) = &values else { panic!("mostly dense regrowth"); };
        if entries.slots.capacity() != previous { reallocations += 1; }
        previous = entries.slots.capacity();
        check_bounds(&values);
    }
    assert!(reallocations < 16, "regrowth must be geometric, not per append");
    assert_eq!(values.get(&1), None);
    assert_eq!(*values.get(&4095).unwrap().1, 4095);
}

#[test]
fn all_iterator_forms_preserve_order_exact_size_and_mutable_ranges() {
    for length in 2..24 {
        let mut values = dense(length);
        values.remove(&1);
        if length > 6 { values.remove(&4); }
        let mut dictionary = values.clone();
        dictionary.promote();
        assert_eq!(format!("{values:?}"), format!("{dictionary:?}"));
        assert_eq!(values, dictionary);
        assert_eq!(dictionary, values);
        let mut left = values.values();
        let mut right = dictionary.values();
        for step in 0..length + 2 {
            assert_eq!(left.len(), right.len());
            assert_eq!(left.size_hint(), right.size_hint());
            if step % 2 == 0 { assert_eq!(left.next(), right.next()); }
            else { assert_eq!(left.next_back(), right.next_back()); }
        }
        for start in 0..length + 1 {
            for end in start..length + 2 {
                let mut actual = values.clone();
                let mut expected = dictionary.clone();
                for map in [&mut actual, &mut expected] {
                    for (_, value) in map.range_values_mut(start..end).rev() { *value += 7; }
                    let mut iter = map.values_mut();
                    let mut step = 0;
                    while iter.len() > 0 {
                        let (_, value) = if step % 2 == 0 { iter.next() } else { iter.next_back() }.unwrap();
                        *value += 1;
                        step += 1;
                    }
                }
                assert_eq!(actual, expected);
                let mut a = actual.into_values();
                let mut b = expected.into_values();
                for step in 0..length + 2 {
                    assert_eq!(a.len(), b.len());
                    if step % 2 == 0 { assert_eq!(a.next(), b.next()); }
                    else { assert_eq!(a.next_back(), b.next_back()); }
                }
            }
        }
    }
}

#[test]
fn retain_after_holes_matches_btree_at_every_predicate_panic() {
    for length in 2..9_u32 {
        for mask in 0..1_u32 << length {
            for panic_at in 0..=length {
                let mut actual = dense(length);
                actual.remove(&1);
                let mut expected: BTreeMap<_, _> = (0..length).filter(|i| *i != 1)
                    .map(|i| (i, (i.to_string(), u64::from(i)))).collect();
                let mut seen_a = Vec::new();
                let mut seen_b = Vec::new();
                let a = catch_unwind(AssertUnwindSafe(|| actual.retain(|i, (key, value)| {
                    seen_a.push(*i); key.push('!'); *value += 10;
                    assert_ne!(*i, panic_at, "predicate panic");
                    mask & (1 << *i) != 0
                })));
                let b = catch_unwind(AssertUnwindSafe(|| expected.retain(|i, (key, value)| {
                    seen_b.push(*i); key.push('!'); *value += 10;
                    assert_ne!(*i, panic_at, "predicate panic");
                    mask & (1 << *i) != 0
                })));
                assert_eq!(a.is_err(), b.is_err());
                assert_eq!(seen_a, seen_b);
                assert_eq!(actual.len(), expected.len());
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                for i in 0..=length { assert_eq!(actual.get(&i), expected.get(&i).map(|(key, value)| (key, value))); }
                check_bounds(&actual);
            }
        }
    }
}

#[test]
fn holey_transitions_move_non_clone_values_and_release_them_once() {
    use std::cell::Cell;
    use std::rc::Rc;
    struct Payload(Rc<Cell<usize>>);
    impl Drop for Payload {
        fn drop(&mut self) { self.0.set(self.0.get() + 1); }
    }
    let drops = Rc::new(Cell::new(0));
    let mut values = IndexedValues::new();
    for index in 0..128_u32 {
        values.insert(index, (index.to_string(), Payload(Rc::clone(&drops))));
    }
    drop(values.remove(&1));
    assert_eq!(drops.get(), 1);
    assert!(matches!(values, IndexedValues::Holey(_)));
    values.retain(|index, _| *index < 9);
    assert_eq!(drops.get(), 120);
    values.insert(1, ("1".into(), Payload(Rc::clone(&drops))));
    values.retain(|_, _| true);
    assert!(matches!(values, IndexedValues::Packed(_)));
    values.clear();
    assert_eq!(drops.get(), 129);
}

#[test]
fn parent_carrier_preserves_exact_keys_wire_and_dense_moves_after_repair() {
    use crate::js_string::JsString;
    use crate::object_model::OrderedStringMap;
    let mut map = OrderedStringMap::new();
    for index in 0..16 { map.insert(index.to_string(), index); }
    map.insert("z".into(), 90);
    let lone = JsString::from_code_units(&[0xd800]);
    map.insert_exact(lone.clone(), 91);
    map.insert("01".into(), 92);
    let wire = serde_json::to_string(&map).unwrap();
    assert_eq!(map.remove("3"), Some(3));
    assert!(matches!(map.array_entries, IndexedValues::Holey(_)));
    assert_eq!(map.get("3"), None);
    map.insert("3".into(), 3);
    assert_eq!(serde_json::to_string(&map).unwrap(), wire);
    let decoded: OrderedStringMap<i32> = serde_json::from_str(&wire).unwrap();
    assert_eq!(map, decoded);
    assert_eq!(map.shift_dense_index_values(16), Some(0));
    map.unshift_dense_index_values(15, vec![30]).unwrap();
    assert_eq!(map.splice_dense_index_values(16, 1, 3, vec![40]), Ok(vec![1, 2, 3]));
    assert_eq!(map.index_values().copied().collect::<Vec<_>>(),
        [30, 40, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    assert_eq!(map.get_exact(&lone), Some(&91));
    assert_eq!(map.get("01"), Some(&92));
    let final_wire = serde_json::to_string(&map).unwrap();
    let restored: OrderedStringMap<i32> = serde_json::from_str(&final_wire).unwrap();
    assert_eq!(restored, map);
}
