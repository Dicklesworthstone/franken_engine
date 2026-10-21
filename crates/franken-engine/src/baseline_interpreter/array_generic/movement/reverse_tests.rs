use super::*;

fn core(throughput: bool) -> InterpreterCore {
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.granted_capabilities = [
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::VmDispatch,
    ].into_iter().collect();
    InterpreterCore::new(config, "sparse-reverse")
}

fn array(core: &mut InterpreterCore, length: u32) -> ObjectId {
    let id = core.alloc_array_with_prototype(None).unwrap();
    core.set_object_property(id, "length".into(), Value::Int(i64::from(length))).unwrap();
    id
}

fn put(core: &mut InterpreterCore, id: ObjectId, index: u64, value: i64) {
    core.set_object_property(id, index.to_string(), Value::Int(value)).unwrap();
}

fn reverse(core: &mut InterpreterCore, id: ObjectId, length: u64) -> Result<(), InterpreterError> {
    core.generic_species_scope(|core| core.generic_reverse_properties(None, id, length))
}

fn module() -> Ir3Module {
    use crate::ast::ParseGoal;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
    let tree = CanonicalEs2020Parser.parse_with_options(
        ParserSource { label: "reverse.js".into(), text: "0".into() },
        ParseGoal::Script,
        &ParserOptions::default(),
    ).unwrap();
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "reverse.js"),
        &LoweringContext::new("reverse", "reverse", "reverse"),
    ).unwrap().ir3
}

#[test]
fn maximum_sparse_reverse_is_connected_to_both_runtime_profiles() {
    let module = module();
    for throughput in [false, true] {
        let mut core = core(throughput);
        let id = array(&mut core, u32::MAX);
        let payload = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(id, "7".into(), Value::Object(payload)).unwrap();
        put(&mut core, id, u64::from(u32::MAX - 1), 9);
        put(&mut core, id, u64::from(u32::MAX / 2), 3);
        let args = RegRange { start: 0, count: 0 };
        assert_eq!(core.generic_array_receiver(&module, BuiltinFunctionKind::ArrayReverse,
            false, Some(&Value::Object(id)), args).unwrap(), Some(id));
        let before = core.native_hole_reads.get();
        assert_eq!(core.array_method_generic(&module, BuiltinFunctionKind::ArrayReverse, id, args)
            .unwrap(), Some(Value::Object(id)));
        let properties = &core.heap[id.0 as usize].properties;
        assert_eq!(properties.get_index(0), Some(&Value::Int(9)));
        assert_eq!(properties.get_index(u32::MAX - 8), Some(&Value::Object(payload)));
        assert_eq!(properties.get_index(u32::MAX / 2), Some(&Value::Int(3)));
        assert_eq!(properties.get_index(7), None);
        assert_eq!(properties.get_index(u32::MAX - 1), None);
        assert_eq!(properties.get("length"), Some(&Value::Int(i64::from(u32::MAX))));
        assert!(core.native_hole_reads.get() - before < 512, "no logical-length scan");
    }
}

#[test]
fn mirrored_bounds_match_every_small_layout_and_reverse_twice() {
    for length in 0..10_u32 {
        for mask in 0..(1_u32 << length) {
            let mut core = core(false);
            let id = array(&mut core, length);
            for index in 0..length {
                if mask & (1 << index) != 0 { put(&mut core, id, u64::from(index), i64::from(index)); }
            }
            for reversed in [true, false] {
                reverse(&mut core, id, u64::from(length)).unwrap();
                for index in 0..length {
                    let original = if reversed { length - 1 - index } else { index };
                    let expected = (mask & (1 << original) != 0).then_some(Value::Int(i64::from(original)));
                    assert_eq!(core.heap[id.0 as usize].properties.get_index(index), expected.as_ref(),
                        "length {length}, mask {mask}, index {index}, reversed {reversed}");
                }
            }
        }
    }
}

#[test]
fn untouched_midpoint_and_empty_span_allocate_no_cursor_storage() {
    let mut core = core(false);
    let id = array(&mut core, u32::MAX);
    put(&mut core, id, u64::from(u32::MAX / 2), 7);
    let before = core.estimated_memory_bytes;
    let objects = core.heap.live_len();
    let mut cursor = MoveCursor::mirrored(u64::from(u32::MAX));
    assert_eq!(cursor.next(&mut core, id).unwrap(), None);
    assert_eq!(core.estimated_memory_bytes, before);
    assert_eq!(core.heap.live_len(), objects);
    core.config.instruction_budget = 0;
    for length in [0, 1] {
        assert_eq!(core.generic_reverse_properties(None, id, length), Ok(()));
    }
    assert!(matches!(core.generic_reverse_properties(None, id, u64::from(u32::MAX)),
        Err(InterpreterError::BudgetExhausted { .. })));
}

#[test]
fn reverse_keeps_a_completed_write_when_upper_deletion_refuses() {
    let mut core = core(false);
    let id = array(&mut core, 131_072);
    put(&mut core, id, 131_071, 8);
    put(&mut core, id, 50_000, 9);
    let key = InterpreterCore::generic_index_key(131_071);
    let mut attributes = core.heap[id.0 as usize].own_property_attributes(&key);
    attributes.configurable = false;
    core.mutate_heap(|heap| {
        heap[id.0 as usize]
            .property_attributes
            .insert(key, attributes);
    });
    assert!(reverse(&mut core, id, 131_072).is_err());
    let properties = &core.heap[id.0 as usize].properties;
    assert_eq!(properties.get_index(0), Some(&Value::Int(8)));
    assert_eq!(properties.get_index(131_071), Some(&Value::Int(8)));
    assert_eq!(properties.get_index(50_000), Some(&Value::Int(9)));
    assert_eq!(properties.get_index(81_071), None, "later pairs must remain untouched");
}

#[test]
fn non_public_context_and_properties_keep_ordinary_pair_probes() {
    let mut core = core(false);
    let id = array(&mut core, 131_072);
    core.active_inline_callback_context_label = Some(Label::Secret);
    let mut cursor = MoveCursor::mirrored(131_072);
    for index in 0..8 { assert_eq!(cursor.next(&mut core, id).unwrap(), Some((index, 131_071-index))); }
    core.active_inline_callback_context_label = None;
    core.set_own_runtime_property_label(id, &InterpreterCore::generic_index_key(100_000), &Label::Secret).unwrap();
    let mut cursor = MoveCursor::mirrored(131_072);
    for index in 0..8 { assert_eq!(cursor.next(&mut core, id).unwrap(), Some((index, 131_071-index))); }
}

#[test]
fn wide_array_like_indices_keep_exact_mirrored_positions() {
    let mut core = core(false);
    let id = core.alloc_object_with_prototype(None).unwrap();
    put(&mut core, id, 3, 7);
    put(&mut core, id, MAX_SAFE_LENGTH - 2, 9);
    let before = core.native_hole_reads.get();
    reverse(&mut core, id, MAX_SAFE_LENGTH).unwrap();
    assert_eq!(core.heap[id.0 as usize].properties.get("1"), Some(&Value::Int(9)));
    assert_eq!(core.heap[id.0 as usize].properties.get(&(MAX_SAFE_LENGTH - 4).to_string()), Some(&Value::Int(7)));
    assert_eq!(core.heap[id.0 as usize].properties.get("3"), None);
    assert!(core.native_hole_reads.get() - before < 512);
}

#[test]
fn upper_value_provenance_reaches_the_lower_write() {
    let mut core = core(false);
    let id = array(&mut core, 131_072);
    put(&mut core, id, 131_071, 7);
    let upper = InterpreterCore::generic_index_key(131_071);
    core.set_own_runtime_property_label(id, &upper, &Label::Secret).unwrap();
    // A short captured interval avoids testing a huge intentionally-unskipped
    // secret suffix. The live-property path is the same for every pair.
    let mut cursor = MoveCursor::mirrored(131_072);
    assert_eq!(cursor.next(&mut core, id).unwrap(), Some((0, 131_071)));
    // Exercise the actual pair with an adjacent secret value instead.
    put(&mut core, id, 1, 7);
    let key = InterpreterCore::generic_index_key(1);
    core.set_own_runtime_property_label(id, &key, &Label::Secret).unwrap();
    reverse(&mut core, id, 2).unwrap();
    assert_eq!(core.runtime_property_label(id, &InterpreterCore::generic_index_key(0)), Label::Secret);
}
