use super::tests::for_each_runtime_profile;
use super::*;

fn sparse_array(core: &mut InterpreterCore, length: u32) -> ObjectId {
    let array = core.alloc_array_from_values(&[]).expect("real Array");
    core.set_object_property(array, "length".into(), Value::Int(i64::from(length)))
        .expect("sparse logical length");
    array
}

fn put(core: &mut InterpreterCore, array: ObjectId, index: u32) {
    core.set_object_property(array, index.to_string(), Value::Int(i64::from(index)))
        .expect("indexed property");
}

fn present(
    core: &mut InterpreterCore,
    cursor: &mut LiveArrayCursor,
    array: ObjectId,
) -> Option<u64> {
    while let Some(index) = cursor.next(core, array).expect("bounded live traversal") {
        if core
            .generic_has(None, array, &InterpreterCore::generic_index_key(index))
            .expect("native HasProperty")
        {
            return Some(index);
        }
    }
    None
}

#[test]
fn sparse_true_arrays_reach_the_live_path_but_hole_visiting_methods_do_not() {
    use BuiltinFunctionKind as K;
    for_each_runtime_profile("sparse-array-dispatch", |mut core| {
        let array = sparse_array(&mut core, u32::MAX);
        put(&mut core, array, 100_000);
        let args = RegRange { start: 0, count: 0 };
        for kind in [
            K::ArrayForEach,
            K::ArrayMap,
            K::ArrayFilter,
            K::ArraySome,
            K::ArrayEvery,
            K::ArrayReduce,
            K::ArrayReduceRight,
            K::ArrayIndexOf,
            K::ArrayLastIndexOf,
        ] {
            assert!(core.sparse_array_iteration_requires_generic(array, kind));
            // Exercise the existing true-Array dispatcher seam, not only the new
            // helper; without this connection the cursor cannot service Arrays.
            assert!(
                core.array_mutation_requires_generic(array, kind, args)
                    .unwrap()
            );
        }
        for kind in [
            K::ArrayIncludes,
            K::ArrayFind,
            K::ArrayFindIndex,
            K::ArrayFindLast,
            K::ArrayFindLastIndex,
            K::ArrayKeys,
            K::ArrayValues,
            K::ArrayEntries,
            K::ArrayJoin,
            K::ArrayPush,
            K::ArraySort,
        ] {
            assert!(!core.sparse_array_iteration_requires_generic(array, kind));
        }
    });
}

#[test]
fn small_and_dense_dispatch_does_not_scan_elements_or_named_metadata() {
    for_each_runtime_profile("sparse-array-density", |mut core| {
        let small = sparse_array(&mut core, (MIN_SPARSE_INTERVAL - 1) as u32);
        assert!(
            !core.sparse_array_iteration_requires_generic(small, BuiltinFunctionKind::ArrayMap)
        );
        let array = sparse_array(&mut core, MIN_SPARSE_INTERVAL as u32);
        // Unrelated names do not turn three numeric entries into a dense array.
        for index in 0..512 {
            core.set_object_property(array, format!("metadata-{index}"), Value::Int(0))
                .unwrap();
        }
        put(&mut core, array, 7);
        assert!(core.sparse_array_iteration_requires_generic(array, BuiltinFunctionKind::ArrayMap));
        for index in 0..(MIN_SPARSE_INTERVAL as u32 / 8) {
            put(&mut core, array, index);
        }
        assert!(
            !core.sparse_array_iteration_requires_generic(array, BuiltinFunctionKind::ArrayMap)
        );
        let before = core.estimated_memory_bytes();
        for _ in 0..128 {
            assert!(
                !core.sparse_array_iteration_requires_generic(array, BuiltinFunctionKind::ArrayMap)
            );
        }
        assert_eq!(core.estimated_memory_bytes(), before);
    });
}

#[test]
fn maximum_length_arrays_seek_live_in_both_directions_without_retained_snapshots() {
    for backwards in [false, true] {
        for_each_runtime_profile("sparse-array-live", |mut core| {
            let array = sparse_array(&mut core, u32::MAX);
            put(&mut core, array, 7);
            put(&mut core, array, u32::MAX - 1);
            let mut cursor = LiveArrayCursor::new(0, u64::from(u32::MAX), backwards, false);
            let before = core.estimated_memory_bytes();
            assert_eq!(
                present(&mut core, &mut cursor, array),
                Some(if backwards {
                    u64::from(u32::MAX - 1)
                } else {
                    7
                })
            );
            assert_eq!(core.estimated_memory_bytes(), before);
            put(&mut core, array, 2_000_000_000);
            assert_eq!(present(&mut core, &mut cursor, array), Some(2_000_000_000));
            assert_eq!(
                present(&mut core, &mut cursor, array),
                Some(if backwards {
                    7
                } else {
                    u64::from(u32::MAX - 1)
                })
            );
            assert_eq!(present(&mut core, &mut cursor, array), None);
            put(&mut core, array, 1_000_000_000);
            assert_eq!(cursor.next(&mut core, array).unwrap(), None);
        });
    }
}

#[test]
fn an_array_prototype_can_supply_unread_indices_without_becoming_a_frozen_snapshot() {
    for_each_runtime_profile("array-as-prototype", |mut core| {
        let prototype = sparse_array(&mut core, u32::MAX);
        put(&mut core, prototype, 100_000);
        let receiver = core.alloc_object_with_prototype(Some(prototype)).unwrap();
        let mut cursor = LiveArrayCursor::new(0, u64::from(u32::MAX), false, false);
        assert_eq!(present(&mut core, &mut cursor, receiver), Some(100_000));
        put(&mut core, prototype, 200_000);
        assert_eq!(present(&mut core, &mut cursor, receiver), Some(200_000));
        assert_eq!(present(&mut core, &mut cursor, receiver), None);
    });
}

#[test]
fn true_array_absence_proofs_still_refuse_non_public_metadata() {
    for_each_runtime_profile("sparse-array-labels", |mut core| {
        let secret = sparse_array(&mut core, u32::MAX);
        core.join_direct_object_mutation_label(secret, &Label::Secret)
            .unwrap();
        assert_eq!(
            core.live_array_like_index(secret, 0, u64::from(u32::MAX), false)
                .unwrap()
                .0,
            NextIndex::Probe
        );
        let array = sparse_array(&mut core, u32::MAX);
        let key = InterpreterCore::generic_index_key(100_000);
        core.set_own_runtime_property_label(array, &key, &Label::Secret)
            .unwrap();
        assert_eq!(
            core.live_array_like_index(array, 0, u64::from(u32::MAX), false)
                .unwrap()
                .0,
            NextIndex::Probe
        );
        let inherited = core.alloc_object_with_prototype(Some(secret)).unwrap();
        assert_eq!(
            core.live_array_like_index(inherited, 0, u64::from(u32::MAX), false)
                .unwrap()
                .0,
            NextIndex::Probe
        );
    });
}

#[test]
fn empty_sparse_array_seeking_remains_budgeted_and_hole_visiting_stays_sequential() {
    for_each_runtime_profile("sparse-array-budget", |mut core| {
        let array = sparse_array(&mut core, u32::MAX);
        for backwards in [false, true] {
            let mut cursor = LiveArrayCursor::new(0, u64::from(u32::MAX), backwards, true);
            for step in 0..8 {
                assert_eq!(
                    cursor.next(&mut core, array).unwrap(),
                    Some(if backwards {
                        u64::from(u32::MAX) - 1 - step
                    } else {
                        step
                    })
                );
                assert_eq!(cursor.probes_left, 0);
            }
        }
        core.config.instruction_budget = 0;
        let mut cursor = LiveArrayCursor::new(0, u64::from(u32::MAX), false, false);
        assert!(matches!(
            cursor.next(&mut core, array),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
    });
}
