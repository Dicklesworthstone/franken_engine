#![forbid(unsafe_code)]

use frankenengine_core::js_string::{CONCAT_NODE_BYTES, JsString};
use std::sync::{Arc, Barrier};

fn expected_point(units: &[u16], index: usize) -> Option<u32> {
    let first = *units.get(index)?;
    if (0xd800..=0xdbff).contains(&first)
        && let Some(&last) = units.get(index + 1)
        && (0xdc00..=0xdfff).contains(&last)
    {
        Some(0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(last) - 0xdc00)
    } else {
        Some(u32::from(first))
    }
}

#[test]
fn mixed_width_reads_match_every_utf16_offset_and_checkpoint_alignment() {
    assert_eq!(std::mem::size_of::<JsString>(), 32);
    for shift in 0..65 {
        let text = format!("{}{}", "a".repeat(shift), "aé中😀𐀀\u{ffff}".repeat(160));
        let units: Vec<u16> = text.encode_utf16().collect();
        let value = JsString::from(text);
        let reserved = value.retained_bytes(16);
        for (index, &unit) in units.iter().enumerate() {
            assert_eq!(
                value.code_unit_at(index),
                Some(unit),
                "shift={shift}, index={index}"
            );
            assert_eq!(value.code_point_at(index), expected_point(&units, index));
        }
        assert_eq!(value.code_unit_at(units.len()), None);
        assert_eq!(value.code_point_at(usize::MAX), None);
        assert_eq!(value.retained_bytes(16), reserved);
        assert_eq!(value.concat_parts().nodes, 0);
    }
}

#[test]
fn indexed_slices_preserve_split_pairs_and_retain_indexable_substrings() {
    let text = "aé中😀𐀀".repeat(400);
    let units: Vec<u16> = text.encode_utf16().collect();
    let value = JsString::from(text);
    for start in [0, 1, 2, 3, 4, 62, 63, 64, 65, 127, 128, 129, 511, 512, 513] {
        for count in [0, 1, 2, 3, 63, 64, 65, 511, 512, 513, 1025] {
            let end = (start + count).min(units.len());
            let slice = value.utf16_slice(start, end);
            assert_eq!(slice.code_units_vec(), units[start..end], "{start}..{end}");
            assert_eq!(
                slice.is_well_formed(),
                String::from_utf16(&units[start..end]).is_ok()
            );
            let reserved = slice.retained_bytes(16);
            for index in 0..slice.utf16_len() {
                assert_eq!(slice.code_unit_at(index), Some(units[start + index]));
            }
            assert_eq!(slice.retained_bytes(16), reserved);
        }
    }
}

#[test]
fn index_storage_is_charged_before_access_and_through_rope_publication() {
    for text in [
        "a".repeat(4096),
        "中".repeat(4096),
        format!("é{}😀", "a".repeat(4096)),
    ] {
        let value = JsString::from(text.clone());
        assert_eq!(value.retained_bytes(16), text.len() as u64 + 16);
    }
    let left = JsString::from("aé中😀".repeat(2048));
    let right = JsString::from("𐀀bΩ".repeat(2048));
    assert!(left.retained_bytes(16) > left.len() as u64 + 16);
    let rope = left.concat(&right);
    let reserved = rope.retained_bytes(16);
    assert!(
        reserved >= left.retained_bytes(16) + right.retained_bytes(16) + CONCAT_NODE_BYTES as u64
    );
    let expected: Vec<u16> = left.encode_utf16().chain(right.encode_utf16()).collect();
    // Explicit publication exercises the root's index, rather than its leaves.
    assert_eq!(
        rope.as_utf8_projection().encode_utf16().collect::<Vec<_>>(),
        expected
    );
    for index in (0..expected.len()).step_by(17) {
        assert_eq!(rope.code_unit_at(index), Some(expected[index]));
    }
    assert_eq!(rope.retained_bytes(16), reserved);
    let settled = rope.utf16_slice(0, rope.utf16_len());
    assert_eq!(settled, rope);
    assert_eq!(settled.concat_parts().nodes, 0);
    let settled_reserved = settled.retained_bytes(16);
    assert_eq!(settled.code_unit_at(513), Some(expected[513]));
    assert_eq!(settled.retained_bytes(16), settled_reserved);
}

#[test]
fn deep_rope_index_fallback_preserves_content_and_linear_accounting() {
    let mut rope = JsString::from("aé中😀".repeat(128));
    let mut expected = rope.code_units_vec();
    for _ in 0..128 {
        let tail = JsString::from("Ω😀".repeat(128));
        expected.extend(tail.encode_utf16());
        rope = rope.concat(&tail);
    }
    let reserved = rope.retained_bytes(16);
    // The index reservation must not add every ancestor's full logical length.
    assert!(reserved < (rope.len() as u64) * 4);
    for index in [0, 1, 63, 64, 65, expected.len() / 2, expected.len() - 1] {
        assert_eq!(rope.code_unit_at(index), Some(expected[index]));
    }
    assert_eq!(rope.retained_bytes(16), reserved);
}

#[test]
fn indexed_storage_preserves_wire_ordering_and_lone_surrogate_healing() {
    let text = "é😀中a".repeat(200);
    let units: Vec<u16> = text.encode_utf16().collect();
    let value = JsString::from(text.clone());
    assert_eq!(
        serde_json::to_string(&value).unwrap(),
        serde_json::to_string(&text).unwrap()
    );
    assert_eq!(value, JsString::from_code_units(&units));
    assert_eq!(
        value.canonical_value(),
        JsString::from_code_units(&units).canonical_value()
    );
    assert_eq!(
        value.cmp(&JsString::from(format!("{text}z"))),
        std::cmp::Ordering::Less
    );
    let mut low = vec![0xde00];
    low.extend(units.iter().copied());
    let healed = JsString::from_code_units(&[0xd83d]).concat(&JsString::from_code_units(&low));
    let mut expected = vec![0xd83d, 0xde00];
    expected.extend(units.iter().copied());
    assert!(healed.is_well_formed());
    assert_eq!(healed.code_units_vec(), expected);
    for index in (0..expected.len()).step_by(13) {
        assert_eq!(
            healed.code_point_at(index),
            expected_point(&expected, index)
        );
    }
    let mut exact = units.clone();
    exact.insert(64, 0xd800);
    let exact = JsString::from_code_units(&exact);
    assert!(!exact.is_well_formed());
    assert_eq!(exact.code_unit_at(64), Some(0xd800));
    assert_eq!(
        serde_json::from_str::<JsString>(&serde_json::to_string(&exact).unwrap()).unwrap(),
        exact
    );
}

#[test]
fn concurrent_join_and_first_index_reads_share_stable_metadata() {
    let left = JsString::from("aé中😀".repeat(1024));
    let right = JsString::from("𐀀z".repeat(1024));
    let units: Arc<[u16]> = left.encode_utf16().chain(right.encode_utf16()).collect();
    let value = Arc::new(left.concat(&right));
    let reserved = value.retained_bytes(16);
    let barrier = Arc::new(Barrier::new(8));
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let value = Arc::clone(&value);
            let units = Arc::clone(&units);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                if worker % 2 == 0 {
                    assert_eq!(
                        value.as_utf8_projection().encode_utf16().count(),
                        units.len()
                    );
                }
                for index in (worker..units.len()).step_by(19) {
                    assert_eq!(value.code_unit_at(index), Some(units[index]));
                    assert_eq!(value.code_point_at(index), expected_point(&units, index));
                    assert_eq!(value.retained_bytes(16), reserved);
                }
            });
        }
    });
}

#[test]
fn unindexed_leaves_reserve_the_joined_strings_future_index() {
    let left = JsString::from("aé中😀".repeat(60));
    let right = left.clone();
    assert_eq!(left.retained_bytes(16), left.len() as u64 + 16);
    let rope = left.concat(&right);
    let reserved = rope.retained_bytes(16);
    // 600 UTF-16 units need ten 64-unit checkpoints, even though neither
    // 300-unit leaf has an index of its own.
    let table_bytes = 10 * std::mem::size_of::<[usize; 2]>() as u64;
    assert!(
        reserved
            >= left.retained_bytes(16)
                + right.retained_bytes(16)
                + CONCAT_NODE_BYTES as u64
                + table_bytes
    );
    let expected: Vec<u16> = left.encode_utf16().chain(right.encode_utf16()).collect();
    assert_eq!(
        rope.as_utf8_projection().encode_utf16().count(),
        expected.len()
    );
    assert_eq!(rope.code_unit_at(301), Some(expected[301]));
    assert_eq!(rope.retained_bytes(16), reserved);
}
