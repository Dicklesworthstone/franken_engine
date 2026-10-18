//! Public compact-rank contract used by mutation-aware Map/Set cursors.
#![forbid(unsafe_code)]

use frankenengine_core::js_string::JsString;
use frankenengine_core::object_model::{OrderedStringMap, canonical_array_index};

fn assert_ranks(map: &OrderedStringMap<usize>) {
    let named: Vec<_> = map
        .keys()
        .filter(|key| canonical_array_index(key.as_str()).is_none())
        .collect();
    for (rank, key) in named.iter().enumerate() {
        let actual = map.insertion_key_at(rank).expect("live named rank");
        assert_eq!(actual, *key);
        assert!(std::ptr::eq(actual, *key), "cursor borrows the stored key");
        assert_eq!(map.insertion_key_position(key), Some(rank));
    }
    for rank in [named.len(), named.len() + 1, usize::MAX] {
        assert!(map.insertion_key_at(rank).is_none());
    }
    assert!(map.insertion_key_position("absent").is_none());
}

#[test]
fn compact_ranks_survive_deletion_reinsertion_and_replacement() {
    let mut map = OrderedStringMap::new();
    for index in 0..128 {
        map.insert(format!("key-{index}"), index);
    }
    assert_ranks(&map);
    for index in [0, 1, 63, 127] {
        let key = format!("key-{index}");
        assert_eq!(map.remove(&key), Some(index));
        assert_ranks(&map);
        map.insert(key.clone(), index + 1000);
        assert_eq!(map.insertion_key_at(127), Some(&key));
        assert_ranks(&map);
    }
    let before: Vec<_> = map.keys().cloned().collect();
    assert_eq!(map.insert("key-64".into(), 9999), Some(64));
    assert_eq!(map.keys().cloned().collect::<Vec<_>>(), before);
    assert_ranks(&map);
}

#[test]
fn cursor_ranks_exclude_numeric_and_exact_only_properties() {
    let lone = JsString::from_code_units(&[0xd800]);
    let mut map = OrderedStringMap::new();
    map.insert("b".into(), 1);
    map.insert("10".into(), 10);
    map.insert_exact(lone.clone(), 8);
    map.insert("2".into(), 2);
    map.insert("01".into(), 3);
    map.insert("\u{fffd}".into(), 4);
    map.insert("4294967295".into(), 5);
    map.insert("4294967294".into(), 6);
    assert_ranks(&map);
    assert_eq!(map.insertion_key_position("2"), None);
    assert_eq!(map.insertion_key_position("4294967294"), None);
    assert_eq!(map.insertion_key_at(0).map(String::as_str), Some("b"));
    assert_eq!(map.insertion_key_at(3).map(String::as_str), Some("4294967295"));
    for key in ["b", "01", "\u{fffd}", "4294967295"] {
        map.remove(key);
        assert_ranks(&map);
    }
    assert!(!map.is_empty(), "numeric properties are still present");
    assert!(map.insertion_key_at(0).is_none());
    assert_eq!(map.get_exact(&lone), Some(&8));
}

#[test]
fn retained_cloned_and_restored_maps_have_the_same_cursor_ranks() {
    let mut map = OrderedStringMap::new();
    for index in 0..160 {
        map.insert(format!("key-{index}"), index);
    }
    for index in (0..160).step_by(3) {
        map.remove(&format!("key-{index}"));
    }
    map.retain(|_, value| *value % 5 != 0);
    assert_ranks(&map);
    let copy = map.clone();
    assert_ranks(&copy);
    let wire = serde_json::to_string(&map).expect("serialize carrier");
    let restored: OrderedStringMap<usize> =
        serde_json::from_str(&wire).expect("restore carrier");
    assert_eq!(restored, map);
    assert_ranks(&restored);
    assert_eq!(
        copy.into_iter().map(|(key, _)| key).collect::<Vec<_>>(),
        map.keys().cloned().collect::<Vec<_>>()
    );
    map.clear();
    assert_ranks(&map);
    map.insert("fresh".into(), 1);
    assert_ranks(&map);
    assert_eq!(map.insertion_key_at(0).map(String::as_str), Some("fresh"));
}

/// Run explicitly in release mode on each compared revision. This reports
/// actual carrier timings, not engine/V8 throughput, and has no timing gate.
/// Construction and deletion are reported too. Delete less than half the
/// keys so the post-deletion measurement does not hide tombstone scan costs
/// behind the storage's half-dead compaction threshold.
#[test]
#[ignore = "release-mode scaling probe; no timing assertions"]
fn named_cursor_scaling_probe() {
    use std::hint::black_box;
    use std::time::Instant;

    for size in [1024usize, 4096, 16384] {
        let start = Instant::now();
        let mut map: OrderedStringMap<usize> = (0..size)
            .map(|index| (format!("key-{index}"), index))
            .collect();
        let construction = start.elapsed();
        let walk = |map: &OrderedStringMap<usize>| {
            let start = Instant::now();
            let mut checksum = 0usize;
            for rank in 0..map.len() {
                let key = black_box(map)
                    .insertion_key_at(black_box(rank))
                    .expect("all probe keys are named");
                checksum = checksum.wrapping_add(black_box(key).len());
            }
            (start.elapsed(), checksum)
        };
        let (full, full_sum) = walk(&map);
        let start = Instant::now();
        let mut removed = 0;
        for index in (0..size).step_by(3) {
            assert_eq!(map.remove(&format!("key-{index}")), Some(index));
            removed += 1;
        }
        let deletion = start.elapsed();
        let (remaining, remaining_sum) = walk(&map);
        assert_eq!(map.len(), size - removed);
        eprintln!(
            "size={size} construction={construction:?} full_walk={full:?} \
             deletion={deletion:?} remaining_walk={remaining:?} \
             checksums={full_sum}/{remaining_sum}"
        );
    }
}
