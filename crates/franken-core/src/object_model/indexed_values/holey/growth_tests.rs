use super::*;
use std::collections::BTreeMap;

fn dense(length: u32) -> IndexedValues<u64> {
    let mut values = IndexedValues::new();
    for index in 0..length {
        values.insert(index, (index.to_string(), u64::from(index)));
    }
    values
}

fn bounds<V>(values: &IndexedValues<V>) -> (usize, usize) {
    let IndexedValues::Holey(entries) = values else {
        panic!("a nearby gap should retain direct indexed storage");
    };
    assert_eq!(entries.live, entries.slots.iter().flatten().count());
    assert!(entries.slots.last().is_some_and(Option::is_some));
    assert!(entries.slots.len() <= 2 * entries.live);
    assert!(entries.slots.capacity() <= 2 * entries.live);
    (entries.slots.len(), entries.slots.capacity())
}

#[test]
fn forward_gaps_keep_numeric_identity_and_existing_key_backing() {
    let mut values = dense(64);
    let addresses: Vec<_> = values.values().map(|(key, _)| key.as_ptr()).collect();
    // The private carrier's numeric identity is independent of spelling.
    values.get_mut(&7).unwrap().0 = "not-an-index".into();
    let changed_address = values.get(&7).unwrap().0.as_ptr();
    assert_eq!(values.insert(66, ("66".into(), 900)), None);
    assert_eq!(bounds(&values).0, 67);
    for index in 0..64_u32 {
        let (key, value) = values.get(&index).unwrap();
        assert_eq!(*value, u64::from(index));
        assert_eq!(key.as_ptr(), if index == 7 { changed_address } else { addresses[index as usize] });
    }
    assert!(values.get(&64).is_none());
    assert!(values.get(&65).is_none());
    assert_eq!(values.get(&66).unwrap().1, 900);
    let mut dictionary = values.clone();
    dictionary.promote();
    assert_eq!(values, dictionary);
    assert_eq!(format!("{values:?}"), format!("{dictionary:?}"));
    values.insert(64, ("64".into(), 64));
    values.insert(65, ("65".into(), 65));
    assert!(values.is_dense_prefix(67));
    assert!(matches!(values, IndexedValues::Holey(_)));
    values.retain(|_, _| true);
    assert!(matches!(values, IndexedValues::Packed(_)));
}

#[test]
fn mostly_dense_forward_builders_grow_geometrically_and_keep_real_holes() {
    for start_holey in [false, true] {
        let mut values = dense(64);
        if start_holey { values.remove(&7); }
        let mut previous_capacity = 0;
        let mut growths = 0;
        let mut last = 63_u32;
        for step in 0..4096_u32 {
            // One missing slot per eight new entries; no backfill is needed
            // to hide density or force the fast representation for this test.
            last += if step % 8 == 0 { 2 } else { 1 };
            values.insert(last, (last.to_string(), u64::from(last)));
            let (_, capacity) = bounds(&values);
            if capacity != previous_capacity { growths += 1; }
            previous_capacity = capacity;
            assert_eq!(values.get(&last).unwrap().1, u64::from(last));
            if step % 8 == 0 { assert!(values.get(&(last - 1)).is_none()); }
        }
        assert!(growths < 20, "geometric growth, not an allocation per gap: {growths}");
        assert_eq!(values.len(), 4160 - usize::from(start_holey));
    }
}

#[test]
fn capacity_plans_refuse_remote_sparse_and_overflow_requests_before_allocation() {
    assert_eq!(gap_capacity(64, 64, 66, 0), Some(130));
    assert_eq!(gap_capacity(64, 67, 100, 130), Some(130));
    // Reuse existing headroom at half occupancy, but do not repeatedly
    // reallocate at that density after headroom runs out.
    assert_eq!(gap_capacity(64, 67, 100, 67), None);
    assert_eq!(gap_capacity(64, 64, 131, 0), None);
    assert_eq!(gap_capacity(4096, 4096, 4096 + MAX_FORWARD_GAP + 1, 0), None);
    assert_eq!(gap_capacity(0, 0, usize::MAX, 0), None);
    assert_eq!(gap_capacity(usize::MAX, usize::MAX, usize::MAX, 0), None);
    assert_eq!(gap_capacity(usize::MAX / 2, 0, 1, 0), None);
    assert_eq!(gap_capacity(8, 8, 9, 32), None);
    for live in 0..96_usize {
        for gap in 1..80_usize {
            let offset = live + gap;
            for capacity in [0, live, 2 * live, 2 * live + 8] {
                if let Some(planned) = gap_capacity(live, live, offset, capacity) {
                    assert!(gap <= MAX_FORWARD_GAP);
                    assert!(offset < planned && planned <= 2 * (live + 1));
                    if planned > capacity {
                        assert!(offset < live + 1 + live.div_ceil(2));
                    }
                }
            }
        }
    }
}

#[test]
fn refused_gaps_preserve_payloads_in_dictionary_and_do_not_oscillate() {
    for start_holey in [false, true] {
        for target in [131_u32, 10_000, u32::MAX - 1, u32::MAX] {
            let mut values = dense(64);
            if start_holey { values.remove(&7); }
            let before: Vec<_> = values.values().cloned().collect();
            assert_eq!(values.insert(target, (target.to_string(), 99)), None);
            assert!(matches!(values, IndexedValues::Dictionary(_)));
            assert_eq!(values.len(), before.len() + 1);
            for (key, value) in before {
                assert_eq!(values.get(&key.parse().unwrap()).unwrap().1, value);
            }
            assert_eq!(values.get(&target).unwrap().1, 99);
            values.remove(&target);
            values.insert(7, ("7".into(), 7));
            assert!(matches!(values, IndexedValues::Dictionary(_)));
        }
    }
    let mut empty = IndexedValues::new();
    empty.insert(u32::MAX, (u32::MAX.to_string(), 1));
    assert!(matches!(empty, IndexedValues::Dictionary(_)));
    assert_eq!(empty.len(), 1);
}

#[test]
fn gap_storage_preserves_all_iterators_and_range_writes() {
    let mut actual = dense(32);
    for index in [34_u32, 37, 40, 42] {
        actual.insert(index, (index.to_string(), u64::from(index)));
    }
    bounds(&actual);
    let mut oracle = actual.clone();
    oracle.promote();
    for start in [0_u32, 31, 32, 33, 35, 41, 44] {
        for end in [start, start + 1, start + 8] {
            let mut a = actual.clone();
            let mut b = oracle.clone();
            for map in [&mut a, &mut b] {
                for (_, value) in map.range_values_mut(start..end).rev() { *value += 100; }
                let mut iter = map.values_mut();
                while let Some((_, value)) = iter.next() {
                    *value += 1;
                    if let Some((_, value)) = iter.next_back() { *value += 2; }
                }
            }
            assert_eq!(a, b);
            let mut a = a.into_values();
            let mut b = b.into_values();
            for step in 0..50 {
                assert_eq!(a.len(), b.len());
                if step % 2 == 0 { assert_eq!(a.next(), b.next()); }
                else { assert_eq!(a.next_back(), b.next_back()); }
            }
        }
    }
    let mut a = actual.values();
    let mut b = oracle.values();
    for step in 0..50 {
        assert_eq!(a.size_hint(), b.size_hint());
        if step % 2 == 0 { assert_eq!(a.next(), b.next()); }
        else { assert_eq!(a.next_back(), b.next_back()); }
    }
}

#[test]
fn gap_conversion_and_fallback_move_non_clone_values_without_extra_drops() {
    use std::cell::Cell;
    use std::rc::Rc;
    struct Owned { data: Box<u64>, drops: Rc<Cell<usize>> }
    impl Drop for Owned {
        fn drop(&mut self) { self.drops.set(self.drops.get() + 1); }
    }
    let drops = Rc::new(Cell::new(0));
    let mut values = IndexedValues::new();
    for index in 0..32_u32 {
        values.insert(index, (index.to_string(), Owned {
            data: Box::new(u64::from(index)), drops: Rc::clone(&drops),
        }));
    }
    let addresses: Vec<_> = values.values()
        .map(|(key, value)| (key.as_ptr(), &*value.data as *const u64)).collect();
    for index in [34_u32, 37, u32::MAX - 1] {
        values.insert(index, (index.to_string(), Owned {
            data: Box::new(u64::from(index)), drops: Rc::clone(&drops),
        }));
        assert_eq!(drops.get(), 0);
        for index in 0..32_u32 {
            let (key, value) = values.get(&index).unwrap();
            assert_eq!((key.as_ptr(), &*value.data as *const u64), addresses[index as usize]);
        }
    }
    assert!(matches!(values, IndexedValues::Dictionary(_)));
    drop(values.remove(&34));
    assert_eq!(drops.get(), 1);
    drop(values);
    assert_eq!(drops.get(), 35);
}

#[test]
fn forward_gap_churn_matches_btree_without_weakening_existing_retain_contracts() {
    for seed in 1..=32_u64 {
        let mut random = seed;
        let mut actual = dense(64);
        let mut expected: BTreeMap<_, _> = (0..64_u32)
            .map(|i| (i, (i.to_string(), u64::from(i)))).collect();
        let mut last = 63_u32;
        for step in 0..512_u32 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let index = if step < 256 {
                last += if step % 8 == 0 { 2 } else { 1 };
                last
            } else { ((random >> 32) as u32) % (last + 4) };
            match if step < 256 { 0 } else { random as u32 % 5 } {
                0 | 1 => {
                    let entry = (index.to_string(), random);
                    let before = expected.insert(index, entry.clone()).map(|(_, value)| value);
                    assert_eq!(actual.insert(index, entry), before);
                }
                2 => assert_eq!(actual.remove(&index), expected.remove(&index)),
                3 => {
                    actual.retain(|key, (_, value)| { *value ^= 7; key % 13 != index % 13 });
                    expected.retain(|key, (_, value)| { *value ^= 7; key % 13 != index % 13 });
                }
                _ => assert_eq!(actual.get(&index), expected.get(&index)),
            }
            assert_eq!(actual.len(), expected.len(), "seed {seed}, step {step}");
            assert_eq!(actual.values().collect::<Vec<_>>(), expected.values().collect::<Vec<_>>());
            assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
            if step < 256 { bounds(&actual); }
        }
    }
}

#[test]
fn parent_wire_exact_names_and_dense_moves_survive_forward_gap_repair() {
    use crate::js_string::JsString;
    use crate::object_model::OrderedStringMap;
    let mut map = OrderedStringMap::new();
    for index in 0..16 { map.insert(index.to_string(), index); }
    let lone = JsString::from_code_units(&[0xd800]);
    map.insert("z".into(), 90);
    map.insert_exact(lone.clone(), 91);
    map.insert("01".into(), 92);
    map.insert("18".into(), 18);
    assert!(matches!(map.array_entries, IndexedValues::Holey(_)));
    assert!(map.get("16").is_none() && map.get("17").is_none());
    let wire = serde_json::to_string(&map).unwrap();
    let restored: OrderedStringMap<i32> = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored, map);
    assert_eq!(serde_json::to_string(&restored).unwrap(), wire);
    map.insert("16".into(), 16);
    map.insert("17".into(), 17);
    assert_eq!(map.shift_dense_index_values(19), Some(0));
    map.unshift_dense_index_values(18, vec![30]).unwrap();
    assert_eq!(map.splice_dense_index_values(19, 1, 3, vec![40]), Ok(vec![1, 2, 3]));
    assert_eq!(map.index_values().copied().collect::<Vec<_>>(),
        [30, 40, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]);
    assert_eq!(map.get_exact(&lone), Some(&91));
    assert_eq!(map.get("01"), Some(&92));
    let wire = serde_json::to_string(&map).unwrap();
    let restored: OrderedStringMap<i32> = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored, map);
}
