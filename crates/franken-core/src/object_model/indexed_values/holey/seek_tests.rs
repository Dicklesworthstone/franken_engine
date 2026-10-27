use super::*;
use crate::object_model::OrderedStringMap;

fn dense(length: u32) -> OrderedStringMap<u32> {
    (0..length).map(|i| (i.to_string(), i)).collect()
}

fn check(map: &OrderedStringMap<u32>, front: u32, back: u32, reverse: bool) {
    let (candidate, work) = map.probe_index_key(front..back, reverse);
    assert!(work <= MAX_INDEX_PROBE_SLOTS);
    if let Some(index) = candidate {
        assert!(front <= index && index < back);
        let skipped = if reverse { index + 1..back } else { front..index };
        assert!(skipped.into_iter().all(|i| map.get_index(i).is_none()));
    } else {
        assert!((front..back).all(|i| map.get_index(i).is_none()));
    }
}

#[test]
fn packed_and_dictionary_seek_use_numeric_order_without_visiting_the_prefix() {
    let mut map = dense(4096);
    for reverse in [false, true] {
        assert_eq!(
            map.probe_index_key(4000..4096, reverse),
            (Some(if reverse { 4095 } else { 4000 }), 1)
        );
        assert_eq!(map.probe_index_key(4096..u32::MAX, reverse), (None, 1));
        assert_eq!(map.probe_index_key(4..4, reverse), (None, 0));
        // Deliberately invalid bounds are input data for the probe, not an
        // attempt to iterate a reversed Rust range.
        let reversed = std::ops::Range { start: 9, end: 3 };
        assert_eq!(map.probe_index_key(reversed, reverse), (None, 0));
    }
    map.insert((u32::MAX - 1).to_string(), 99);
    assert!(matches!(map.array_entries, IndexedValues::Dictionary(_)));
    assert_eq!(
        map.probe_index_key(5000..u32::MAX, false),
        (Some(u32::MAX - 1), 1)
    );
    assert_eq!(
        map.probe_index_key(5000..u32::MAX, true),
        (Some(u32::MAX - 1), 1)
    );
    assert_eq!(map.probe_index_key(4096..u32::MAX - 1, true), (None, 1));
}

#[test]
fn hole_runs_return_an_unproved_boundary_before_work_becomes_unbounded() {
    let mut map = dense(512);
    for index in 128..256 { map.remove(&index.to_string()); }
    assert!(matches!(map.array_entries, IndexedValues::Holey(_)));
    assert_eq!(map.probe_index_key(128..256, false), (Some(192), 64));
    assert_eq!(map.probe_index_key(128..256, true), (Some(191), 64));
    assert_eq!(map.probe_index_key(192..256, false), (None, 64));
    assert_eq!(map.probe_index_key(128..192, true), (None, 64));
    assert_eq!(map.probe_index_key(512..u32::MAX, false), (None, 0));
    for reverse in [false, true] { check(&map, 120, 264, reverse); }
}

#[test]
fn every_storage_form_has_a_conservative_frontier_for_all_small_ranges() {
    for length in 0..32_u32 {
        for mode in 0..3 {
            let mut map = dense(length);
            if mode == 1 && length > 2 {
                map.remove("1");
            } else if mode == 2 {
                map.array_entries.promote();
            }
            for front in 0..=length + 2 {
                for back in front..=length + 2 {
                    for reverse in [false, true] { check(&map, front, back, reverse); }
                }
            }
        }
    }
}

#[test]
fn seeking_excludes_non_index_and_exact_only_keys_and_preserves_key_backing() {
    use crate::js_string::JsString;
    let mut map = dense(128);
    for name in ["01", "-0", "4294967295", "z"] { map.insert(name.into(), 900); }
    map.insert_exact(JsString::from_code_units(&[0xd800]), 901);
    let pointer = map.array_entries.get(&127).unwrap().0.as_ptr();
    map.remove("3");
    // Numeric identity belongs to the slot, not this private mutable spelling.
    *map.array_entries.get_mut(&127).unwrap().0 = "not-numeric".into();
    let replacement_pointer = map.array_entries.get(&127).unwrap().0.as_ptr();
    assert_ne!(pointer, replacement_pointer);
    assert_eq!(map.probe_index_key(127..u32::MAX, false), (Some(127), 1));
    assert_eq!(map.probe_index_key(128..u32::MAX, false), (None, 0));
    assert_eq!(map.array_entries.get(&127).unwrap().0.as_ptr(), replacement_pointer);
}

#[test]
fn successive_seeks_are_live_under_delete_reinsert_and_direction_changes() {
    let mut map = OrderedStringMap::new();
    map.insert("100000".into(), 1);
    map.insert("300000".into(), 3);
    assert_eq!(map.probe_index_key(1..400000, false).0, Some(100000));
    map.remove("300000");
    map.insert("200000".into(), 2);
    assert_eq!(map.probe_index_key(100001..400000, false).0, Some(200000));
    map.insert("150000".into(), 4);
    assert_eq!(map.probe_index_key(1..200000, true).0, Some(150000));
    assert_eq!(map.probe_index_key(200001..400000, false).0, None);
}

#[test]
fn seeking_neither_clones_nor_moves_owned_payloads() {
    struct Owned(Box<u8>); // Intentionally no Clone.
    let mut map = OrderedStringMap::new();
    for index in 0..16 { map.insert(index.to_string(), Owned(Box::new(index as u8))); }
    map.remove("7");
    let payload = map.get_index(15).unwrap().0.as_ref() as *const u8;
    for _ in 0..256 {
        assert_eq!(map.probe_index_key(7..16, false).0, Some(8));
        assert_eq!(map.probe_index_key(0..16, true).0, Some(15));
    }
    assert_eq!(map.get_index(15).unwrap().0.as_ref() as *const u8, payload);
}
