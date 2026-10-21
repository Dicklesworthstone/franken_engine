use super::*;

fn core() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::VmDispatch,
    ]
    .into_iter()
    .collect();
    config.instruction_budget = 100_000;
    InterpreterCore::new(config, "live-flatten")
}

fn array(core: &mut InterpreterCore, len: u32) -> ObjectId {
    let id = core.alloc_array_with_prototype(None).expect("array");
    core.set_object_property(id, "length".into(), Value::Int(i64::from(len)))
        .expect("length");
    id
}

fn flatten(
    core: &mut InterpreterCore,
    target: ObjectId,
    source: ObjectId,
    len: u64,
    depth: f64,
) -> Result<(), InterpreterError> {
    core.generic_species_scope(|core| {
        core.generic_flatten_into(None, target, source, len, depth, None)
    })
}

#[test]
fn maximum_length_nested_arrays_do_not_scan_their_holes() {
    let mut core = core();
    let root = array(&mut core, u32::MAX);
    let child = array(&mut core, u32::MAX);
    let target = array(&mut core, 0);
    core.set_object_property(root, "17".into(), Value::Object(child)).unwrap();
    core.set_object_property(root, "4294967293".into(), Value::Int(9)).unwrap();
    core.set_object_property(child, "4294967293".into(), Value::Int(7)).unwrap();
    let before = core.native_hole_reads.get();
    flatten(&mut core, target, root, u64::from(u32::MAX), f64::INFINITY).unwrap();
    assert_eq!(core.heap[target.0 as usize].properties.get_index(0), Some(&Value::Int(7)));
    assert_eq!(core.heap[target.0 as usize].properties.get_index(1), Some(&Value::Int(9)));
    assert_eq!(core.heap[target.0 as usize].properties.get("length"), Some(&Value::Int(2)));
    assert!(core.native_hole_reads.get() - before < 2048);
    assert_eq!(core.json_parse_temporary_bytes, 0);
}

#[test]
fn depth_zero_keeps_child_identity_and_shared_children_repeat() {
    let mut core = core();
    let child = array(&mut core, 1);
    core.set_object_property(child, "0".into(), Value::Int(7)).unwrap();
    let root = array(&mut core, 2);
    core.set_object_property(root, "0".into(), Value::Object(child)).unwrap();
    core.set_object_property(root, "1".into(), Value::Object(child)).unwrap();
    for depth in [0.0, 1.0, f64::INFINITY] {
        let target = array(&mut core, 0);
        flatten(&mut core, target, root, 2, depth).unwrap();
        let expected = if depth == 0.0 { Value::Object(child) } else { Value::Int(7) };
        assert_eq!(core.heap[target.0 as usize].properties.get_index(0), Some(&expected));
        assert_eq!(core.heap[target.0 as usize].properties.get_index(1), Some(&expected));
        assert_eq!(core.json_parse_temporary_bytes, 0);
    }
}

#[test]
fn empty_children_preserve_length_and_mutation_provenance_on_species_aliases() {
    for label in [Label::Public, Label::Secret] {
        for mutation_label in [false, true] {
            for append_public in [false, true] {
                let mut core = core();
                let child = array(&mut core, 0);
                if mutation_label {
                    core.join_object_mutation_label(child, &label).unwrap();
                } else {
                    core.set_own_property_label(child, "length", &label)
                        .unwrap();
                }
                let source = array(&mut core, if append_public { 2 } else { 1 });
                core.set_object_property(source, "0".into(), Value::Object(child))
                    .unwrap();
                if append_public {
                    core.set_object_property(source, "1".into(), Value::Int(9))
                        .unwrap();
                }
                let target = array(&mut core, 0);
                flatten(
                    &mut core,
                    target,
                    source,
                    if append_public { 2 } else { 1 },
                    1.0,
                )
                .unwrap();
                assert_eq!(core.own_property_label(target, "length"), label);
                if append_public {
                    assert_eq!(
                        core.heap[target.0 as usize].properties.get_index(0),
                        Some(&Value::Int(9))
                    );
                    assert_eq!(core.own_property_label(target, "0"), label);
                }
                assert_eq!(core.json_parse_temporary_bytes, 0);
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}

#[test]
fn empty_source_custom_provenance_respects_live_memory_headroom() {
    for allow_temporary in [false, true] {
        let mut core = core();
        let source = array(&mut core, 0);
        let target = array(&mut core, 0);
        let label = Label::Custom {
            name: "flatten-source-length".repeat(256),
            level: 6,
        };
        core.set_own_property_label(source, "length", &label)
            .unwrap();
        let before = core.estimated_memory_bytes();
        if !allow_temporary {
            core.config.max_total_memory_bytes =
                before + frame_bytes(4) + InterpreterCore::estimate_label_bytes(&label) - 1;
        }
        let outcome = flatten(&mut core, target, source, 0, 1.0);
        if allow_temporary {
            outcome.expect("ordinary headroom retains the observed Custom provenance");
            assert_eq!(core.own_property_label(target, "length"), label);
        } else {
            assert!(matches!(
                outcome,
                Err(InterpreterError::MemoryBudgetExceeded { .. })
            ));
            assert_eq!(core.own_property_label(target, "length"), Label::Public);
            assert_eq!(core.estimated_memory_bytes(), before);
        }
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn stack_capacity_is_charged_until_the_operation_releases_it() {
    let mut core = core();
    let source = array(&mut core, 0);
    core.json_reserve_temporary(37).unwrap();
    let mut stack = Vec::new();
    let mut reserved = 0;
    for _ in 0..257 {
        core.push_flatten_frame(
            &mut stack, &mut reserved, FlattenFrame::new(source, 0, 1.0, false),
        ).unwrap();
        assert_eq!(reserved, frame_bytes(stack.capacity()));
        assert_eq!(core.json_parse_temporary_bytes, 37 + reserved);
    }
    stack.clear();
    // Capacity, not length, is retained while sibling sources may reuse it.
    assert_eq!(core.json_parse_temporary_bytes, 37 + reserved);
    drop(stack);
    core.json_release_temporary(reserved);
    assert_eq!(core.json_parse_temporary_bytes, 37);
    core.json_release_temporary(37);
}

#[test]
fn an_infinite_depth_cycle_exhausts_work_and_releases_the_stack() {
    let mut core = core();
    let source = array(&mut core, 1);
    let target = array(&mut core, 0);
    core.set_object_property(source, "0".into(), Value::Object(source)).unwrap();
    core.config.instruction_budget = 128;
    core.json_reserve_temporary(37).unwrap();
    assert!(matches!(
        flatten(&mut core, target, source, 1, f64::INFINITY),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    assert_eq!(core.json_parse_temporary_bytes, 37);
    assert!(core.heap[target.0 as usize].properties.get_index(0).is_none());
    core.json_release_temporary(37);
}

#[test]
fn stack_growth_obeys_live_memory_headroom_and_cleans_up_refusal() {
    let mut core = core();
    let source = array(&mut core, 1);
    let target = array(&mut core, 0);
    core.set_object_property(source, "0".into(), Value::Object(source)).unwrap();
    core.config.max_total_memory_bytes = core.estimated_memory_bytes + 8192;
    assert!(matches!(
        flatten(&mut core, target, source, 1, f64::INFINITY),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert!(core.heap[target.0 as usize].properties.get_index(0).is_none());
}

#[test]
fn even_an_empty_flatten_checks_cancellation_and_releases_scratch() {
    let mut core = core();
    let source = array(&mut core, 0);
    let target = array(&mut core, 0);
    let token = CancellationToken::new();
    token.cancel();
    core.config.cancellation_token = Some(token);
    assert!(matches!(
        flatten(&mut core, target, source, 0, 1.0),
        Err(InterpreterError::Cancelled)
    ));
    assert_eq!(core.json_parse_temporary_bytes, 0);
}

#[test]
fn observed_element_provenance_reaches_the_species_output() {
    let mut core = core();
    let source = array(&mut core, 1);
    let target = array(&mut core, 0);
    core.set_object_property(source, "0".into(), Value::Int(7)).unwrap();
    let key = InterpreterCore::generic_index_key(0);
    core.set_own_runtime_property_label(source, &key, &Label::Secret).unwrap();
    flatten(&mut core, target, source, 1, 1.0).unwrap();
    assert_eq!(core.own_stored_runtime_property_label(target, &key), Label::Secret);
    assert_eq!(core.json_parse_temporary_bytes, 0);
}

#[test]
fn sparse_source_flat_and_flat_map_use_the_shared_walker_in_both_profiles() {
    use crate::ast::ParseGoal;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = "var a=[];a.length=4294967295;a[17]=2;a[4294967293]=6; \
        a.flat().join(',')+'|'+a.flatMap(v=>[v,v+1]).join(',')";
    let tree = CanonicalEs2020Parser.parse_with_options(
        ParserSource { label: "live-flatten.js".into(), text: source.into() },
        ParseGoal::Script,
        &ParserOptions::default(),
    ).expect("parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "live-flatten.js"),
        &LoweringContext::new("flat-trace", "flat-decision", "flat-policy"),
    ).expect("lower").ir3;
    for mut config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
        config.instruction_budget = 50_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ].into_iter().collect();
        let mut core = InterpreterCore::new(config, "live-flatten-source");
        let result = core.execute(&module).expect("sparse flattening must finish within fuel");
        assert_eq!(result.value, Value::str("2,6|2,3,6,7"));
        assert_eq!(core.json_parse_temporary_bytes, 0);
    }
}
