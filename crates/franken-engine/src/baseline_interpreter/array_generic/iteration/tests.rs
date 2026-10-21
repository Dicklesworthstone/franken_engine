use super::*;

pub(super) fn for_each_runtime_profile(trace: &str, mut run: impl FnMut(InterpreterCore)) {
    for config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        run(InterpreterCore::new(config, trace));
    }
}

fn object(core: &mut InterpreterCore, prototype: Option<ObjectId>) -> ObjectId {
    core.alloc_object_with_prototype(prototype)
        .expect("ordinary object")
}

fn put(core: &mut InterpreterCore, object: ObjectId, index: u64, value: i64) {
    core.set_object_property(object, index.to_string(), Value::Int(value))
        .unwrap();
}

fn next_present(
    core: &mut InterpreterCore,
    cursor: &mut LiveArrayCursor,
    object: ObjectId,
) -> Option<u64> {
    while let Some(index) = cursor.next(core, object).unwrap() {
        if core
            .generic_has(None, object, &InterpreterCore::generic_index_key(index))
            .unwrap()
        {
            return Some(index);
        }
    }
    None
}

#[test]
fn forward_and_reverse_cursors_observe_new_keys_without_revisiting_old_indices() {
    for backwards in [false, true] {
        for_each_runtime_profile("live-indices", |mut core| {
            let object = object(&mut core, None);
            put(&mut core, object, 0, 1);
            put(&mut core, object, 100_000, 3);
            let mut cursor = LiveArrayCursor::new(0, 1 << 32, backwards, false);
            assert_eq!(
                next_present(&mut core, &mut cursor, object),
                Some(if backwards { 100_000 } else { 0 })
            );
            put(&mut core, object, 50_000, 2);
            // A new property outside the captured length must not extend traversal.
            put(&mut core, object, 1 << 32, 4);
            assert_eq!(next_present(&mut core, &mut cursor, object), Some(50_000));
            assert_eq!(
                next_present(&mut core, &mut cursor, object),
                Some(if backwards { 0 } else { 100_000 })
            );
            assert_eq!(next_present(&mut core, &mut cursor, object), None);
            // Once exhausted, later insertion cannot restart this operation.
            put(&mut core, object, 70_000, 5);
            assert_eq!(cursor.next(&mut core, object).unwrap(), None);
        });
    }
}

#[test]
fn inherited_candidates_use_numeric_order_and_never_duplicate_shadowed_keys() {
    for_each_runtime_profile("live-prototypes", |mut core| {
        let prototype = object(&mut core, None);
        put(&mut core, prototype, 100_000, 9);
        put(&mut core, prototype, 40_000, 8);
        let receiver = object(&mut core, Some(prototype));
        put(&mut core, receiver, 40_000, 2);
        put(&mut core, receiver, 0, 1);
        let mut cursor = LiveArrayCursor::new(0, 1 << 32, false, false);
        assert_eq!(next_present(&mut core, &mut cursor, receiver), Some(0));
        put(&mut core, prototype, 20_000, 7);
        assert_eq!(next_present(&mut core, &mut cursor, receiver), Some(20_000));
        assert_eq!(next_present(&mut core, &mut cursor, receiver), Some(40_000));
        assert_eq!(
            next_present(&mut core, &mut cursor, receiver),
            Some(100_000)
        );
        assert_eq!(next_present(&mut core, &mut cursor, receiver), None);
    });
}

#[test]
fn named_indices_past_u32_and_close_to_the_safe_length_limit_remain_exact() {
    for_each_runtime_profile("live-wide-indices", |mut core| {
        let object = object(&mut core, None);
        for index in [u64::from(u32::MAX), 1 << 40, MAX_SAFE_LENGTH - 1] {
            put(&mut core, object, index, 1);
        }
        for name in ["01", "-0", "+1", "1e9", "4294967295.0", "9007199254740991"] {
            core.set_object_property(object, name.into(), Value::Int(99))
                .unwrap();
        }
        let mut cursor = LiveArrayCursor::new(0, MAX_SAFE_LENGTH, false, false);
        for expected in [u64::from(u32::MAX), 1 << 40, MAX_SAFE_LENGTH - 1] {
            assert_eq!(next_present(&mut core, &mut cursor, object), Some(expected));
        }
        assert_eq!(next_present(&mut core, &mut cursor, object), None);
    });
}

#[test]
fn inventory_debt_prevents_a_full_scan_for_each_dense_prefix_element() {
    for_each_runtime_profile("live-scan-debt", |mut core| {
        let object = object(&mut core, None);
        for index in 0..512 {
            put(&mut core, object, index, index as i64);
        }
        let mut cursor = LiveArrayCursor::new(0, 1 << 32, false, false);
        for index in 0..512 {
            assert_eq!(cursor.next(&mut core, object).unwrap(), Some(index));
            assert!(
                cursor.probes_left <= 1,
                "a present edge requires no inventory"
            );
        }
        assert_eq!(next_present(&mut core, &mut cursor, object), None);
        assert!(
            cursor.probes_left >= 512,
            "the absent tail was inventoried only once"
        );
    });
}

#[test]
fn non_public_receiver_or_prototype_metadata_cannot_prove_skipped_absence() {
    for_each_runtime_profile("live-index-labels", |mut core| {
        let secret = object(&mut core, None);
        core.join_direct_object_mutation_label(secret, &Label::Secret)
            .unwrap();
        assert_eq!(
            core.live_array_like_index(secret, 0, 1 << 32, false)
                .unwrap()
                .0,
            NextIndex::Probe
        );
        let receiver = object(&mut core, Some(secret));
        assert_eq!(
            core.live_array_like_index(receiver, 0, 1 << 32, false)
                .unwrap()
                .0,
            NextIndex::Probe
        );
        let receiver = object(&mut core, None);
        let key = InterpreterCore::generic_index_key(70000);
        core.set_own_runtime_property_label(receiver, &key, &Label::Secret)
            .unwrap();
        assert_eq!(
            core.live_array_like_index(receiver, 0, 1 << 32, false)
                .unwrap()
                .0,
            NextIndex::Probe
        );
    });
}

#[test]
fn hole_visiting_methods_and_small_intervals_emit_every_index() {
    for_each_runtime_profile("live-index-holes", |mut core| {
        let object = object(&mut core, None);
        for backwards in [false, true] {
            let mut cursor = LiveArrayCursor::new(5, 9, backwards, false);
            let mut actual = Vec::new();
            while let Some(index) = cursor.next(&mut core, object).unwrap() {
                actual.push(index);
            }
            let expected = if backwards {
                vec![8, 7, 6, 5]
            } else {
                vec![5, 6, 7, 8]
            };
            assert_eq!(actual, expected);
            let mut cursor = LiveArrayCursor::new(0, 1 << 32, backwards, true);
            for step in 0..32 {
                let expected = if backwards {
                    (1 << 32) - step - 1
                } else {
                    step
                };
                assert_eq!(cursor.next(&mut core, object).unwrap(), Some(expected));
                assert_eq!(
                    cursor.probes_left, 0,
                    "a find-family method never takes an inventory"
                );
            }
        }
    });
}

#[test]
fn decimal_index_parser_matches_canonical_safe_integer_names() {
    for index in [
        0,
        1,
        9,
        10,
        100,
        65_536,
        u64::from(u32::MAX),
        1 << 40,
        MAX_SAFE_LENGTH - 1,
    ] {
        let name = index.to_string();
        assert_eq!(array_like_index(&name), Some(index));
        for invalid in [format!("+{name}"), format!("{name}.0"), format!("0{name}")] {
            assert_eq!(array_like_index(&invalid), None);
        }
    }
    for invalid in [
        "",
        "-0",
        " 1",
        "1 ",
        "１",
        "1e3",
        "NaN",
        "Infinity",
        "9007199254740991",
        "18446744073709551615",
    ] {
        assert_eq!(array_like_index(invalid), None);
    }
}

#[test]
fn inherited_dense_prefix_amortizes_inventory_work_into_ordinary_probes() {
    for_each_runtime_profile("live-inherited-debt", |mut core| {
        let prototype = object(&mut core, None);
        for index in 0..256 {
            put(&mut core, prototype, index, index as i64);
        }
        let receiver = object(&mut core, Some(prototype));
        let mut cursor = LiveArrayCursor::new(0, 1 << 32, false, false);
        assert_eq!(cursor.next(&mut core, receiver).unwrap(), Some(0));
        let debt = cursor.probes_left;
        assert!(debt >= 256);
        for index in 1..256 {
            assert_eq!(cursor.next(&mut core, receiver).unwrap(), Some(index));
            assert_eq!(cursor.probes_left, debt - index);
        }
        assert_eq!(next_present(&mut core, &mut cursor, receiver), None);
    });
}
