use super::*;

fn runtime() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    InterpreterCore::new(config, "buffer-view-registry")
}

fn buffer(core: &mut InterpreterCore, shared: bool) -> ObjectId {
    let id = core.alloc_buffer_object(16, shared).unwrap();
    core.mutate_heap(|heap| {
        heap[id.0 as usize].array_buffer.as_deref_mut().unwrap().max_byte_length = Some(64);
    });
    id
}

fn view(core: &mut InterpreterCore, buffer: ObjectId, offset: usize, fixed: Option<usize>) -> ObjectId {
    let length = fixed.unwrap_or(16 - offset);
    let id = core.alloc_data_view_object(buffer, offset, length).unwrap();
    core.register_buffer_view(id, Some(ViewBounds {
        fixed_length: fixed,
        out_of_bounds: false,
    })).unwrap();
    id
}

// The old production candidate/survivor path remains used for explicit
// candidate lists. Exercise it directly as the registry-refresh oracle.
fn reference(core: &mut InterpreterCore, buffer: ObjectId) -> Result<(), InterpreterError> {
    let candidates = core.buffer_backing(buffer)?.views.clone();
    core.refresh_buffer_view_candidates(buffer, candidates.into_iter())
}

fn set_length(core: &mut InterpreterCore, buffer: ObjectId, length: usize) {
    core.mutate_heap(|heap| {
        let object = &mut heap[buffer.0 as usize];
        object.array_buffer.as_deref_mut().unwrap().bytes.resize(length, 0);
        object.properties.insert("byteLength".to_string(), Value::Int(length as i64));
    });
    core.sync_estimated_memory_bytes().unwrap();
}

fn assert_accounted(core: &InterpreterCore) {
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    assert!(core.pending_exception.is_none());
}

fn graph(core: &mut InterpreterCore, shared: bool) -> (ObjectId, Vec<ObjectId>) {
    let id = buffer(core, shared);
    let a = view(core, id, 4, Some(4));
    let b = view(core, id, 8, None);
    let c = view(core, id, 0, None);
    let other = buffer(core, shared);
    let foreign = view(core, other, 0, None);
    let ordinary = core.alloc_object_with_prototype(None).unwrap();
    // Model a weak registry containing reclaimed, reused, foreign and repeated
    // IDs. Neither stale membership nor duplicate order may change live views.
    core.set_buffer_view_registry(id, vec![ordinary, a, ObjectId(u32::MAX), b, foreign, a, c])
        .unwrap();
    (id, vec![a, b, c, foreign])
}

fn compare_views(actual: &InterpreterCore, expected: &InterpreterCore, ids: &[ObjectId]) {
    for id in ids {
        let a = &actual.heap[id.0 as usize];
        let b = &expected.heap[id.0 as usize];
        let av = a.data_view.as_ref().unwrap();
        let bv = b.data_view.as_ref().unwrap();
        assert_eq!(av.buffer, bv.buffer);
        assert_eq!(av.byte_offset, bv.byte_offset);
        assert_eq!(av.byte_length, bv.byte_length);
        assert_eq!(
            av.bounds.map(|bounds| (bounds.fixed_length, bounds.out_of_bounds)),
            bv.bounds.map(|bounds| (bounds.fixed_length, bounds.out_of_bounds))
        );
        for key in ["byteLength", "byteOffset"] {
            assert_eq!(a.properties.get(key), b.properties.get(key));
        }
    }
}

#[test]
fn registered_refresh_matches_old_views_order_and_accounting_through_resize_cycles() {
    for shared in [false, true] {
        let mut actual = runtime();
        let mut expected = runtime();
        let (a, ids) = graph(&mut actual, shared);
        let (b, reference_ids) = graph(&mut expected, shared);
        assert_eq!(a, b);
        assert_eq!(ids, reference_ids);
        let pointer = actual.buffer_backing(a).unwrap().views.as_ptr();
        let capacity = actual.buffer_backing(a).unwrap().views.capacity();
        let lengths = if shared { vec![16, 24, 32, 64] } else { vec![12, 8, 4, 0, 17, 32, 16] };
        for length in lengths {
            set_length(&mut actual, a, length);
            set_length(&mut expected, b, length);
            actual.refresh_buffer_views(a).unwrap();
            reference(&mut expected, b).unwrap();
            compare_views(&actual, &expected, &ids);
            assert_eq!(actual.buffer_backing(a).unwrap().views, vec![ids[0], ids[1], ids[0], ids[2]]);
            assert_eq!(actual.buffer_backing(a).unwrap().views, expected.buffer_backing(b).unwrap().views);
            assert_eq!(actual.buffer_backing(a).unwrap().views.as_ptr(), pointer);
            assert_eq!(actual.buffer_backing(a).unwrap().views.capacity(), capacity);
            assert_eq!(actual.estimated_memory_bytes(), expected.estimated_memory_bytes());
            assert_accounted(&actual);
            assert_accounted(&expected);
        }
    }
}

#[test]
fn all_stale_registry_compacts_in_place_and_accepts_new_registration() {
    let mut core = runtime();
    let id = buffer(&mut core, false);
    let ordinary = core.alloc_object_with_prototype(None).unwrap();
    core.set_buffer_view_registry(id, vec![ordinary, ObjectId(u32::MAX), ordinary]).unwrap();
    let pointer = core.buffer_backing(id).unwrap().views.as_ptr();
    let capacity = core.buffer_backing(id).unwrap().views.capacity();
    core.refresh_buffer_views(id).unwrap();
    assert!(core.buffer_backing(id).unwrap().views.is_empty());
    assert_eq!(core.buffer_backing(id).unwrap().views.as_ptr(), pointer);
    assert_eq!(core.buffer_backing(id).unwrap().views.capacity(), capacity);
    let new = view(&mut core, id, 0, None);
    assert_eq!(core.buffer_backing(id).unwrap().views, vec![new]);
    core.resize_buffer_bytes(id, 24).unwrap();
    assert_eq!(core.heap[new.0 as usize].data_view.as_ref().unwrap().byte_length, 24);
    assert_eq!(core.buffer_backing(id).unwrap().views.as_ptr(), pointer);
    assert_accounted(&core);
}

#[test]
fn repeated_live_refresh_reuses_registry_and_keeps_inherited_scratch() {
    let mut core = runtime();
    let id = buffer(&mut core, false);
    for index in 0..512 {
        view(&mut core, id, index % 8, None);
    }
    core.json_reserve_temporary(77).unwrap();
    let before = core.estimated_memory_bytes();
    let pointer = core.buffer_backing(id).unwrap().views.as_ptr();
    let capacity = core.buffer_backing(id).unwrap().views.capacity();
    core.config.max_total_memory_bytes = before;
    for _ in 0..32 {
        core.refresh_buffer_views(id).unwrap();
        assert_eq!(core.buffer_backing(id).unwrap().views.len(), 512);
        assert_eq!(core.buffer_backing(id).unwrap().views.as_ptr(), pointer);
        assert_eq!(core.buffer_backing(id).unwrap().views.capacity(), capacity);
        assert_eq!(core.json_parse_temporary_bytes, 77);
        assert_eq!(core.estimated_memory_bytes(), before);
    }
    core.json_release_temporary(77);
    assert_accounted(&core);
}

#[test]
fn failed_view_readmission_keeps_original_registry_and_old_partial_effects() {
    let mut actual = runtime();
    let mut expected = runtime();
    let (a, ids) = graph(&mut actual, false);
    let (b, _) = graph(&mut expected, false);
    for (core, id) in [(&mut actual, a), (&mut expected, b)] {
        set_length(core, id, 0);
        reference(core, id).unwrap();
        // Add a stale prefix so premature compaction would change retry order.
        let mut list = core.buffer_backing(id).unwrap().views.clone();
        list.insert(0, ObjectId(u32::MAX));
        core.set_buffer_view_registry(id, list).unwrap();
        set_length(core, id, 16);
        core.json_reserve_temporary(77).unwrap();
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
    }
    let original = actual.buffer_backing(a).unwrap().views.clone();
    let got = actual.refresh_buffer_views(a);
    let want = reference(&mut expected, b);
    assert!(matches!(got, Err(InterpreterError::MemoryBudgetExceeded { .. })));
    assert_eq!(got, want);
    assert_eq!(actual.buffer_backing(a).unwrap().views, original);
    assert_eq!(expected.buffer_backing(b).unwrap().views, original);
    compare_views(&actual, &expected, &ids);
    assert_eq!(actual.json_parse_temporary_bytes, 77);
    assert_eq!(actual.estimated_memory_bytes(), expected.estimated_memory_bytes());
    assert!(actual.pending_exception.is_none());
    // The original implementation mutates a view before its accounting delta
    // can refuse. This test preserves that behavior, not a new atomicity claim.
}

#[test]
fn registered_detachment_matches_old_path_and_fixed_buffer_discovery_survives() {
    let mut actual = runtime();
    let mut expected = runtime();
    let (a, ids) = graph(&mut actual, false);
    let (b, _) = graph(&mut expected, false);
    actual.detach_array_buffer(a).unwrap();
    expected.detach_array_buffer_storage(b).unwrap();
    reference(&mut expected, b).unwrap();
    compare_views(&actual, &expected, &ids);
    assert_eq!(actual.buffer_backing(a).unwrap().views, expected.buffer_backing(b).unwrap().views);
    assert_accounted(&actual);
    assert_accounted(&expected);

    let id = actual.alloc_array_buffer_object(16).unwrap();
    let view = actual.alloc_data_view_object(id, 4, 4).unwrap();
    assert!(actual.buffer_backing(id).unwrap().views.is_empty());
    actual.detach_array_buffer(id).unwrap();
    assert!(actual.heap[view.0 as usize].data_view.as_ref().unwrap().bounds.unwrap().out_of_bounds);
    assert!(actual.heap[view.0 as usize].properties.get("byteLength").is_none());
    assert_accounted(&actual);
}

const SOURCE: &str = r#"
    var kinds = [Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array,
        Int32Array, Uint32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array];
    var checks = 0;
    function check(value, message) { if (!value) throw message; }
    function viewLength(v) { try { return v.byteLength; } catch (e) { if (e instanceof TypeError) return -1; throw e; } }
    for (var C of kinds) {
        var b = new ArrayBuffer(16, {maxByteLength: 64});
        var t = new C(b), f = new C(b, 0, 1), o = new C(b, 8);
        var d = new DataView(b, 8), fixed = new DataView(b, 8, 4);
        for (var n of [16, 8, 0, 24, 16]) {
            b.resize(n);
            check(t.length === Math.floor(n / C.BYTES_PER_ELEMENT), 'tracking length');
            check(t.byteLength === t.length * C.BYTES_PER_ELEMENT, 'tracking bytes');
            check(f.length === (n < C.BYTES_PER_ELEMENT ? 0 : 1), 'fixed length');
            check(o.length === (n < 8 ? 0 : Math.floor((n - 8) / C.BYTES_PER_ELEMENT)), 'offset length');
            check(o.byteOffset === (n < 8 ? 0 : 8), 'offset');
            check(viewLength(d) === (n < 8 ? -1 : n - 8), 'DataView tracking');
            check(viewLength(fixed) === (n < 12 ? -1 : 4), 'DataView fixed');
            checks++;
        }
    }
    var reentrant = new ArrayBuffer(16, {maxByteLength: 64}), made, coerced = 0;
    reentrant.resize({valueOf: function () { coerced++; made = new Uint8Array(reentrant, 8); return 4; }});
    check(coerced === 1 && made.length === 0, 'coercion-created view');
    reentrant.resize(24);
    check(made.length === 16, 'coercion-created view revival');
    var transferred = reentrant.transfer();
    check(made.length === 0 && transferred.byteLength === 24 && transferred.resizable, 'transfer');
    var s = new SharedArrayBuffer(8, {maxByteLength: 32});
    var st = new Uint16Array(s), sf = new Uint16Array(s, 0, 2), sd = new DataView(s, 4);
    s.grow(24);
    check(st.length === 12 && sf.length === 2 && sd.byteLength === 20, 'shared growth');
    [kinds.length, checks, coerced, made.length, transferred.byteLength, st.length, sd.byteLength].join('|');
"#;

#[test]
fn public_resize_transfer_and_grow_keep_all_typed_view_and_coercion_semantics() {
    let tree = crate::parser_api_stability::parse_script(SOURCE).unwrap();
    let lowered = crate::lowering_pipeline::lower_ir0_to_ir3(
        &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "registered-buffer-views.js"),
        &crate::lowering_pipeline::LoweringContext::new("registry", "resize", "builtin-only"),
    ).unwrap();
    let mut core = runtime();
    let result = core.execute(&lowered.ir3).unwrap();
    assert_eq!(result.value, Value::str("11|55|1|0|24|12|20"));
    assert_accounted(&core);
}
