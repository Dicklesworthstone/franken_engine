use super::*;

fn core() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::HeapAllocate, RuntimeCapability::Builtin, RuntimeCapability::VmDispatch,
    ].into_iter().collect();
    InterpreterCore::new(config, "sparse-moves")
}

fn array(core: &mut InterpreterCore, length: u32) -> ObjectId {
    let object = core.alloc_array_with_prototype(None).unwrap();
    core.set_object_property(object, "length".into(), Value::Int(i64::from(length))).unwrap();
    object
}

fn put(core: &mut InterpreterCore, object: ObjectId, index: u64, value: i64) {
    core.set_object_property(object, index.to_string(), Value::Int(value)).unwrap();
}

fn get(core: &InterpreterCore, object: ObjectId, index: u32) -> Option<&Value> {
    core.heap[object.0 as usize].properties.get_index(index)
}

fn move_range(
    core: &mut InterpreterCore, object: ObjectId, from: u64, to: u64, count: u64, backwards: bool,
) -> Result<(), InterpreterError> {
    core.generic_species_scope(|core| core.generic_move_range(None, object, from, to, count, backwards))
}

#[test]
fn destination_only_keys_are_deleted_and_source_values_preserve_identity() {
    let mut core = core();
    let object = array(&mut core, 262_144);
    let payload = core.alloc_object_with_prototype(None).unwrap();
    put(&mut core, object, 7, 70);
    core.set_object_property(object, "200000".into(), Value::Object(payload)).unwrap();
    let before = core.native_hole_reads.get();
    move_range(&mut core, object, 131_072, 0, 131_072, false).unwrap();
    assert_eq!(get(&core, object, 7), None);
    assert_eq!(get(&core, object, 68_928), Some(&Value::Object(payload)));
    assert_eq!(get(&core, object, 200_000), Some(&Value::Object(payload)));
    assert!(core.native_hole_reads.get() - before < 256, "do not visit every absent pair");
}

#[test]
fn maximum_length_overlaps_keep_direction_and_unwritten_tail() {
    for backwards in [false, true] {
        let mut core = core();
        let object = array(&mut core, u32::MAX);
        put(&mut core, object, 7, 7);
        put(&mut core, object, u64::from(u32::MAX - 1), 9);
        let (from, to) = if backwards { (0, 1) } else { (1, 0) };
        let before = core.native_hole_reads.get();
        move_range(&mut core, object, from, to, u64::from(u32::MAX - 1), backwards).unwrap();
        assert_eq!(get(&core, object, 7), None);
        assert_eq!(get(&core, object, if backwards { 8 } else { 6 }), Some(&Value::Int(7)));
        if backwards {
            assert_eq!(get(&core, object, u32::MAX - 1), None);
        } else {
            assert_eq!(get(&core, object, u32::MAX - 2), Some(&Value::Int(9)));
            assert_eq!(get(&core, object, u32::MAX - 1), Some(&Value::Int(9)));
        }
        assert!(core.native_hole_reads.get() - before < 256);
    }
}

#[test]
fn inherited_indices_and_wide_safe_integer_ranges_use_live_candidates() {
    let mut core = core();
    let prototype = core.alloc_object_with_prototype(None).unwrap();
    put(&mut core, prototype, 150_000, 7);
    let object = core.alloc_object_with_prototype(Some(prototype)).unwrap();
    move_range(&mut core, object, 131_072, 0, 131_072, false).unwrap();
    assert_eq!(get(&core, object, 18_928), Some(&Value::Int(7)));
    let wide = core.alloc_object_with_prototype(None).unwrap();
    put(&mut core, wide, MAX_SAFE_LENGTH - 1, 99);
    let before = core.native_hole_reads.get();
    move_range(&mut core, wide, MAX_SAFE_LENGTH - 65_536, 0, 65_536, false).unwrap();
    assert_eq!(get(&core, wide, 65_535), Some(&Value::Int(99)));
    assert!(core.native_hole_reads.get() - before < 256);
}

#[test]
fn a_source_at_the_edge_does_not_scan_destination_metadata_before_its_read() {
    let mut core = core();
    let object = array(&mut core, 400_000);
    put(&mut core, object, 0, 7);
    for i in 0..512 {
        core.set_object_property(object, format!("metadata-{i}"), Value::Int(0)).unwrap();
    }
    let before = core.native_hole_reads.get();
    let mut cursor = MoveCursor::new(0, 200_000, 131_072, false);
    assert_eq!(cursor.next(&mut core, object).unwrap(), Some((0, 200_000)));
    assert_eq!(core.native_hole_reads.get(), before);
    assert!(cursor.probes_left <= 1);
}

#[test]
fn non_public_control_and_object_metadata_never_skip_missing_deletes() {
    let mut core = core();
    let object = array(&mut core, 262_144);
    core.active_inline_callback_context_label = Some(Label::Secret);
    let mut cursor = MoveCursor::new(131_072, 0, 131_072, false);
    for i in 0..16 {
        assert_eq!(cursor.next(&mut core, object).unwrap(), Some((131_072 + i, i)));
    }
    core.active_inline_callback_context_label = None;
    core.join_direct_object_mutation_label(object, &Label::Secret).unwrap();
    let mut cursor = MoveCursor::new(131_072, 0, 131_072, false);
    for i in 0..16 {
        assert_eq!(cursor.next(&mut core, object).unwrap(), Some((131_072 + i, i)));
    }
}

#[test]
fn empty_ranges_do_nothing_but_nonempty_absence_proofs_remain_budgeted() {
    let mut core = core();
    let object = array(&mut core, u32::MAX);
    core.config.instruction_budget = 0;
    assert!(move_range(&mut core, object, 0, 0, 0, false).is_ok());
    assert!(matches!(
        move_range(&mut core, object, 1, 0, u64::from(u32::MAX - 1), false),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
}
