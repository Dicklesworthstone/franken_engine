//! Capacity transitions must not turn a linear tail-mutation stream into
//! quadratic reallocation requests. These test the real storage carriers,
//! not timing thresholds or a replacement implementation of the allocator.

use super::{IndexedValues, shrink_target};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

fn storage_capacity<V>(values: &IndexedValues<V>) -> usize {
    match values {
        IndexedValues::Packed(entries) => entries.capacity(),
        IndexedValues::Holey(entries) => entries.slots.capacity(),
        IndexedValues::Dictionary(_) => panic!("dense tail churn must not build a dictionary"),
    }
}

fn check_bound<V>(values: &IndexedValues<V>) {
    match values {
        IndexedValues::Packed(entries) => {
            if entries.is_empty() {
                assert_eq!(entries.capacity(), 0);
            } else {
                // Keep the original strict len < capacity/2 trigger, including
                // its one-slot odd-capacity boundary and Vec's tiny allocation.
                assert!(entries.capacity() <= (2 * entries.len() + 1).max(4));
            }
        }
        IndexedValues::Holey(entries) => {
            assert!(entries.is_bounded());
            assert!(entries.slots.capacity() <= 2 * entries.live);
        }
        IndexedValues::Dictionary(_) => panic!("unexpected sparse migration"),
    }
}

fn packed(length: u32) -> IndexedValues<u64> {
    IndexedValues::Packed(
        (0..length)
            .map(|index| (index.to_string(), u64::from(index)))
            .collect(),
    )
}

// Record capacity transitions after EACH operation; checking only at the end
// of a grow/shrink cycle would conceal the original pair of reallocations.
fn sample<V>(values: &IndexedValues<V>, previous: &mut usize, changes: &mut usize) {
    let current = storage_capacity(values);
    if current != *previous {
        *changes += 1;
        *previous = current;
    }
    check_bound(values);
}

fn churn(values: &mut IndexedValues<u64>, span: u32) -> usize {
    let mut previous = storage_capacity(values);
    let mut changes = 0;
    for top in (span / 2 + 1..=span).rev() {
        assert_eq!(values.insert(top, (top.to_string(), u64::from(top))), None);
        sample(values, &mut previous, &mut changes);
        assert_eq!(values.remove(&top), Some((top.to_string(), u64::from(top))));
        sample(values, &mut previous, &mut changes);
        assert_eq!(
            values.remove(&(top - 1)),
            Some(((top - 1).to_string(), u64::from(top - 1)))
        );
        sample(values, &mut previous, &mut changes);
    }
    changes
}

#[test]
fn shrink_targets_fit_the_existing_envelope_even_at_word_boundaries() {
    let edges = [
        usize::MAX / 3,
        usize::MAX / 2,
        usize::MAX / 2 + 1,
        usize::MAX - 1,
        usize::MAX,
    ];
    for live in (0..=1024).chain(edges) {
        for span in [live, live.saturating_add(live / 4), live.saturating_mul(2)] {
            let target = shrink_target(live, span);
            assert!(target >= span);
            assert!(target <= live.saturating_mul(2));
            assert!(target >= live.saturating_add(live / 2));
        }
    }
    assert_eq!(shrink_target(0, 0), 0);
    assert_eq!(shrink_target(1, 1), 1);
    assert_eq!(shrink_target(8, 8), 12);
    assert_eq!(shrink_target(8, 15), 15);
}

#[test]
fn packed_append_two_pop_drain_does_not_resize_on_every_cycle() {
    for length in [256, 1024, 4096, 16384] {
        let mut values = packed(length);
        let key = values.get(&1).unwrap().0.as_ptr();
        let changes = churn(&mut values, length);
        assert!(changes <= 16, "{changes} capacity changes for {length} slots");
        assert_eq!(values, packed(length / 2));
        assert_eq!(values.get(&1).unwrap().0.as_ptr(), key);
    }
}

#[test]
fn holey_append_two_pop_drain_preserves_absence_and_geometric_headroom() {
    for length in [256, 1024, 4096, 16384] {
        let mut values = packed(length);
        assert_eq!(values.remove(&0), Some(("0".into(), 0)));
        let key = values.get(&1).unwrap().0.as_ptr();
        let changes = churn(&mut values, length);
        assert!(changes <= 16, "{changes} holey capacity changes for {length} slots");
        assert!(matches!(values, IndexedValues::Holey(_)));
        assert_eq!(values.len(), length as usize / 2 - 1);
        assert_eq!(values.get(&0), None);
        assert_eq!(values.get(&1).unwrap().0.as_ptr(), key);
        for index in 1..length / 2 {
            assert_eq!(values.get(&index).unwrap().1, u64::from(index));
        }
    }
}

#[test]
fn recovered_and_cloned_dense_carriers_do_not_reintroduce_exact_fit_churn() {
    let original = packed(4096);
    let mut cloned = original.clone();
    assert!(churn(&mut cloned, 4096) <= 16);
    assert_eq!(original.len(), 4096);
    let mut recovered = original.clone();
    recovered.promote();
    recovered.retain(|_, _| true);
    assert!(matches!(recovered, IndexedValues::Packed(_)));
    assert!(churn(&mut recovered, 4096) <= 16);
    assert_eq!(recovered, cloned);
}

#[test]
fn complete_tail_drains_release_the_backing_and_restart_as_packed() {
    for holey in [false, true] {
        let mut values = packed(4096);
        if holey {
            values.remove(&0);
        }
        let mut previous = storage_capacity(&values);
        let mut changes = 0;
        for index in (0..4096).rev() {
            values.remove(&index);
            sample(&values, &mut previous, &mut changes);
        }
        assert!(changes < 64);
        assert!(matches!(values, IndexedValues::Packed(_)));
        assert_eq!(storage_capacity(&values), 0);
        assert_eq!(values.insert(0, ("0".into(), 99)), None);
        assert_eq!(values.get(&0), Some(&("0".into(), 99)));
    }
}

#[test]
fn resize_cycles_move_non_clone_values_and_drop_each_ownership_once() {
    struct Owned {
        identity: u32,
        payload: Box<[u8; 8]>,
        drops: Rc<RefCell<Vec<u32>>>,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            self.drops.borrow_mut().push(self.identity);
        }
    }
    for holey in [false, true] {
        let drops = Rc::new(RefCell::new(Vec::new()));
        let owned = |identity| Owned {
            identity,
            payload: Box::new([7; 8]),
            drops: Rc::clone(&drops),
        };
        let mut values = IndexedValues::Packed(
            (0..256_u32).map(|i| (i.to_string(), owned(i))).collect(),
        );
        if holey {
            drop(values.remove(&0));
        }
        let (key, value) = values.get(&1).unwrap();
        let addresses = (key.as_ptr(), value.payload.as_ptr());
        for (step, top) in (129..=256_u32).rev().enumerate() {
            let identity = 256 + step as u32;
            assert!(values.insert(top, (top.to_string(), owned(identity))).is_none());
            let removed = values.remove(&top).unwrap();
            assert_eq!(removed.1.identity, identity);
            check_bound(&values);
            drop(removed);
            let removed = values.remove(&(top - 1)).unwrap();
            assert_eq!(removed.1.identity, top - 1);
            check_bound(&values);
            drop(removed);
        }
        let (key, value) = values.get(&1).unwrap();
        assert_eq!((key.as_ptr(), value.payload.as_ptr()), addresses);
        drop(values);
        let mut identities = drops.borrow().clone();
        identities.sort_unstable();
        assert_eq!(identities, (0..384).collect::<Vec<_>>());
    }
}

#[test]
fn removal_normalizes_capacity_before_a_returned_value_destructor_panics() {
    struct PanicOnce(Rc<Cell<bool>>);
    impl Drop for PanicOnce {
        fn drop(&mut self) {
            assert!(!self.0.replace(false), "deliberate returned-value drop panic");
        }
    }
    for holey in [false, true] {
        let trigger = Rc::new(Cell::new(false));
        let mut values = IndexedValues::Packed(
            (0..256_u32).map(|i| (i.to_string(), PanicOnce(Rc::clone(&trigger)))).collect(),
        );
        if holey {
            drop(values.remove(&0));
        }
        // Force the first tail removal to cross the original shrink trigger.
        match &mut values {
            IndexedValues::Packed(entries) => entries.reserve_exact(256),
            IndexedValues::Holey(entries) => entries.slots.reserve_exact(256),
            IndexedValues::Dictionary(_) => unreachable!(),
        }
        trigger.set(true);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(values.remove(&255));
        }));
        assert!(result.is_err());
        assert!(values.get(&255).is_none());
        assert!(values.get(&254).is_some());
        check_bound(&values);
        drop(values);
    }
}

#[test]
fn capacity_history_preserves_parent_wire_order_holes_and_present_undefined() {
    use super::super::OrderedStringMap;
    use crate::js_string::JsString;

    let lone = JsString::from_code_units(&[0xd800]);
    let mut actual = OrderedStringMap::new();
    actual.insert("z".into(), Some(900_u32));
    actual.insert_exact(lone.clone(), Some(901));
    actual.insert("a".into(), Some(902));
    for index in 0..256_u32 {
        actual.insert(index.to_string(), (index != 1).then_some(index));
    }
    actual.remove("3");
    let mut expected = actual.clone();
    expected.array_entries.promote();
    for top in (129..=256_u32).rev() {
        for map in [&mut actual, &mut expected] {
            map.insert(top.to_string(), Some(top));
            assert_eq!(map.remove(&top.to_string()), Some(Some(top)));
            assert_eq!(map.remove(&(top - 1).to_string()), Some(Some(top - 1)));
        }
        check_bound(&actual.array_entries);
    }
    assert_eq!(actual.get_index(1), Some(&None));
    assert_eq!(actual.get_index(3), None);
    assert_eq!(actual.get_exact(&lone), Some(&Some(901)));
    assert_eq!(actual, expected);
    let wire = serde_json::to_string(&actual).unwrap();
    assert_eq!(wire, serde_json::to_string(&expected).unwrap());
    let restored: OrderedStringMap<Option<u32>> = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored, actual);
}
