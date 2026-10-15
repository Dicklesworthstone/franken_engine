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

fn length_mutation_module() -> Ir3Module {
    use crate::ast::ParseGoal;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
    let tree = CanonicalEs2020Parser.parse_with_options(
        ParserSource { label: "length-mutations.js".into(), text: "0".into() },
        ParseGoal::Script,
        &ParserOptions::default(),
    ).expect("parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "length-mutations.js"),
        &LoweringContext::new("length-mutations", "length-mutations", "length-mutations"),
    ).expect("lower").ir3
}

#[test]
fn shift_dispatch_moves_maximum_sparse_length_with_bounded_work() {
    let module = length_mutation_module();
    let mut core = core();
    let object = array(&mut core, u32::MAX);
    let payload = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object, "0".into(), Value::Object(payload)).unwrap();
    put(&mut core, object, 17, 7);
    put(&mut core, object, u64::from(u32::MAX - 1), 9);
    let args = RegRange { start: 0, count: 0 };
    assert_eq!(core.generic_array_receiver(&module, BuiltinFunctionKind::ArrayShift,
        false, Some(&Value::Object(object)), args).unwrap(), Some(object));
    let before = core.native_hole_reads.get();
    let result = core.array_method_generic(&module, BuiltinFunctionKind::ArrayShift, object, args)
        .expect("sparse shift");
    assert_eq!(result, Some(Value::Object(payload)));
    assert_eq!(get(&core, object, 0), None);
    assert_eq!(get(&core, object, 16), Some(&Value::Int(7)));
    assert_eq!(get(&core, object, u32::MAX - 2), Some(&Value::Int(9)));
    assert_eq!(get(&core, object, u32::MAX - 1), None);
    assert_eq!(core.heap[object.0 as usize].properties.get("length"),
        Some(&Value::Int(i64::from(u32::MAX - 1))));
    assert!(core.native_hole_reads.get() - before < 512,
        "native dispatch must not scan the logical length");
}

#[test]
fn unshift_dispatch_moves_backwards_before_inserting_arguments() {
    let module = length_mutation_module();
    let mut core = core();
    let object = array(&mut core, u32::MAX - 2);
    let payload = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(object, "7".into(), Value::Object(payload)).unwrap();
    put(&mut core, object, u64::from(u32::MAX - 3), 9);
    core.seed_register(0, Value::Int(1)).unwrap();
    core.seed_register(1, Value::Int(2)).unwrap();
    let args = RegRange { start: 0, count: 2 };
    assert_eq!(core.generic_array_receiver(&module, BuiltinFunctionKind::ArrayUnshift,
        false, Some(&Value::Object(object)), args).unwrap(), Some(object));
    let before = core.native_hole_reads.get();
    assert_eq!(core.array_method_generic(&module, BuiltinFunctionKind::ArrayUnshift, object, args)
        .expect("sparse unshift"), Some(Value::Int(i64::from(u32::MAX))));
    assert_eq!(get(&core, object, 0), Some(&Value::Int(1)));
    assert_eq!(get(&core, object, 1), Some(&Value::Int(2)));
    assert_eq!(get(&core, object, 7), None);
    assert_eq!(get(&core, object, 9), Some(&Value::Object(payload)));
    assert_eq!(get(&core, object, u32::MAX - 1), Some(&Value::Int(9)));
    assert_eq!(core.heap[object.0 as usize].properties.get("length"),
        Some(&Value::Int(i64::from(u32::MAX))));
    assert!(core.native_hole_reads.get() - before < 512);
}

#[test]
fn splice_copies_and_shifts_maximum_sparse_arrays_without_length_sized_work() {
    let module = length_mutation_module();
    for growing in [false, true] {
        let mut core = core();
        let initial = if growing { u32::MAX - 2 } else { u32::MAX };
        let object = array(&mut core, initial);
        let payload = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object, "5".into(), Value::Object(payload)).unwrap();
        put(&mut core, object, 3_000_000_000, 9);
        core.seed_register(0, Value::Int(4)).unwrap();
        core.seed_register(1, Value::Int(if growing { 0 } else { 2_000_000_000 })).unwrap();
        core.seed_register(2, Value::Int(7)).unwrap();
        core.seed_register(3, Value::Int(8)).unwrap();
        let args = RegRange { start: 0, count: if growing { 4 } else { 3 } };
        let before = core.native_hole_reads.get();
        let scratch = core.json_parse_temporary_bytes;
        let result = core.array_method_generic(&module, BuiltinFunctionKind::ArraySplice, object, args)
            .expect("sparse splice").expect("method implemented");
        let Value::Object(removed) = result else { panic!("removed Array") };
        assert_eq!(core.json_parse_temporary_bytes, scratch);
        assert!(core.native_hole_reads.get() - before < 1024,
            "all three splice phases must avoid the logical hole count");
        if growing {
            assert_eq!(get(&core, object, 4), Some(&Value::Int(7)));
            assert_eq!(get(&core, object, 5), Some(&Value::Int(8)));
            assert_eq!(get(&core, object, 7), Some(&Value::Object(payload)));
            assert_eq!(get(&core, object, 3_000_000_002), Some(&Value::Int(9)));
            assert_eq!(core.heap[removed.0 as usize].properties.get("length"), Some(&Value::Int(0)));
            assert_eq!(core.heap[object.0 as usize].properties.get("length"),
                Some(&Value::Int(i64::from(u32::MAX))));
        } else {
            assert_eq!(get(&core, removed, 1), Some(&Value::Object(payload)));
            assert_eq!(core.heap[removed.0 as usize].properties.get("length"),
                Some(&Value::Int(2_000_000_000)));
            assert_eq!(get(&core, removed, 0), None);
            assert_eq!(get(&core, object, 4), Some(&Value::Int(7)));
            assert_eq!(get(&core, object, 5), None);
            assert_eq!(get(&core, object, 1_000_000_001), Some(&Value::Int(9)));
            assert_eq!(get(&core, object, 3_000_000_000), None);
            assert_eq!(core.heap[object.0 as usize].properties.get("length"),
                Some(&Value::Int(2_294_967_296)));
        }
    }
}

#[test]
fn tail_deletion_stops_at_the_first_refused_index_in_descending_order() {
    let mut core = core();
    let object = array(&mut core, u32::MAX);
    for index in [7_u64, 90_000, u64::from(u32::MAX - 1)] { put(&mut core, object, index, 1); }
    let key = InterpreterCore::generic_index_key(90_000);
    let mut attributes = core.heap[object.0 as usize].own_property_attributes(&key);
    attributes.configurable = false;
    core.mutate_heap(|heap| {
        heap[object.0 as usize].property_attributes.insert(key, attributes);
    });
    let before = core.native_hole_reads.get();
    let result = core.generic_species_scope(|core| {
        core.generic_delete_range(None, object, 0, u64::from(u32::MAX), true)
    });
    assert!(result.is_err(), "a non-configurable own property must refuse deletion");
    assert_eq!(get(&core, object, u32::MAX - 1), None);
    assert_eq!(get(&core, object, 90_000), Some(&Value::Int(1)));
    assert_eq!(get(&core, object, 7), Some(&Value::Int(1)));
    assert_eq!(core.heap[object.0 as usize].properties.get("length"),
        Some(&Value::Int(i64::from(u32::MAX))), "deleting indices never sets length");
    assert!(core.native_hole_reads.get() - before < 512);
}

#[test]
fn tail_deletion_keeps_work_admission_for_public_and_non_public_empty_storage() {
    for context in [Label::Public, Label::Secret] {
        let mut core = core();
        let object = array(&mut core, u32::MAX);
        core.config.instruction_budget = 0;
        core.active_inline_callback_context_label = Some(context);
        assert!(core.generic_delete_range(None, object, 0, 0, true).is_ok());
        let result = core.generic_delete_range(None, object, 0, u64::from(u32::MAX), true);
        assert!(matches!(result, Err(InterpreterError::BudgetExhausted { .. })),
            "both ordinary probes and absence proofs must be admitted: {result:?}");
        assert_eq!(core.heap[object.0 as usize].properties.get("length"),
            Some(&Value::Int(i64::from(u32::MAX))));
    }
}
