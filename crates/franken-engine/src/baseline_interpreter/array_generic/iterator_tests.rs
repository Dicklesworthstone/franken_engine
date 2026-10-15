//! Exercise the generic dispatch arm, not a duplicate iterator implementation.
use super::*;
use crate::ast::ParseGoal;
use crate::ir_contract::Ir0Module;
use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn module() -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource { label: "lazy-array.js".into(), text: "0".into() },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "lazy-array.js"),
        &LoweringContext::new("iterator-trace", "iterator-decision", "iterator-policy"),
    )
    .expect("lower")
    .ir3
}

fn core(throughput: bool) -> InterpreterCore {
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ].into_iter().collect();
    InterpreterCore::new(config, "lazy-array")
}

fn source(core: &mut InterpreterCore, length: i64) -> ObjectId {
    let object = core.alloc_object_with_prototype(None).expect("source");
    core.set_object_property(object, "length".into(), Value::Int(length)).unwrap();
    object
}

fn iterator(core: &mut InterpreterCore, module: &Ir3Module, source: ObjectId,
    kind: BuiltinFunctionKind) -> Value
{
    core.array_method_generic(module, kind, source, RegRange { start: 0, count: 0 })
        .expect("iterator construction")
        .expect("supported method")
}

#[test]
fn construction_retains_one_source_and_has_length_independent_charges() {
    let module = module();
    for throughput in [false, true] {
        for kind in [BuiltinFunctionKind::ArrayKeys, BuiltinFunctionKind::ArrayValues,
            BuiltinFunctionKind::ArrayEntries]
        {
            let mut costs = Vec::new();
            for length in [1, 1_000_000_000, 9_007_199_254_740_991] {
                let mut core = core(throughput);
                let source = source(&mut core, length);
                let before = core.estimated_memory_bytes;
                let objects = core.heap.live_len();
                let value = iterator(&mut core, &module, source, kind);
                let Value::Iterator(handle) = value else { panic!("not a native iterator") };
                let Some(RuntimeIteratorState::ForOf(state)) = core.iterators.get(handle as usize)
                else { panic!("not for-of state") };
                assert!(state.values.is_empty(), "no eager element snapshot");
                assert_eq!(state.array.as_ref().unwrap().object_id, source);
                assert_eq!(state.next_index, 0);
                assert_eq!(core.heap.live_len(), objects, "no entry-pair objects at creation");
                costs.push(core.estimated_memory_bytes - before);
            }
            assert!(costs[0] > 0, "native state must remain charged");
            assert!(costs.iter().all(|cost| *cost == costs[0]), "{costs:?}");
        }
    }
}

#[test]
fn next_reads_current_elements_and_length_and_never_restarts_after_done() {
    let module = module();
    let mut core = core(false);
    let source = source(&mut core, 1);
    let value = iterator(&mut core, &module, source, BuiltinFunctionKind::ArrayValues);
    core.set_object_property(source, "0".into(), Value::Int(7)).unwrap();
    assert_eq!(core.advance_for_of_iterator(None, value.clone()).unwrap(), Some(Value::Int(7)));
    core.set_object_property(source, "length".into(), Value::Int(2)).unwrap();
    core.set_object_property(source, "1".into(), Value::Int(8)).unwrap();
    assert_eq!(core.advance_for_of_iterator(None, value.clone()).unwrap(), Some(Value::Int(8)));
    assert_eq!(core.advance_for_of_iterator(None, value.clone()).unwrap(), None);
    core.set_object_property(source, "length".into(), Value::Int(3)).unwrap();
    core.set_object_property(source, "2".into(), Value::Int(9)).unwrap();
    assert_eq!(core.advance_for_of_iterator(None, value).unwrap(), None);
}

#[test]
fn keys_do_not_observe_index_labels_but_values_do() {
    let module = module();
    let mut core = core(false);
    let source = source(&mut core, 1);
    core.set_object_property(source, "0".into(), Value::Int(7)).unwrap();
    let key = InterpreterCore::generic_index_key(0);
    core.set_own_runtime_property_label(source, &key, &Label::Secret).unwrap();
    let keys = iterator(&mut core, &module, source, BuiltinFunctionKind::ArrayKeys);
    let values = iterator(&mut core, &module, source, BuiltinFunctionKind::ArrayValues);
    core.replace_pending_hostcall_result_label(None).unwrap();
    assert_eq!(core.advance_for_of_iterator(None, keys).unwrap(), Some(Value::Int(0)));
    assert_eq!(core.pending_hostcall_result_label.as_ref().unwrap_or(&Label::Public), &Label::Public);
    assert_eq!(core.advance_for_of_iterator(None, values).unwrap(), Some(Value::Int(7)));
    assert_eq!(core.pending_hostcall_result_label.as_ref(), Some(&Label::Secret));
}

#[test]
fn entries_allocate_only_on_demand_and_are_independent_pairs() {
    let module = module();
    let mut core = core(false);
    let source = source(&mut core, 2);
    core.set_object_property(source, "0".into(), Value::Int(7)).unwrap();
    core.set_object_property(source, "1".into(), Value::Int(8)).unwrap();
    let entries = iterator(&mut core, &module, source, BuiltinFunctionKind::ArrayEntries);
    let Some(Value::Object(first)) = core.advance_for_of_iterator(None, entries.clone()).unwrap()
    else { panic!("first pair") };
    core.set_object_property(first, "1".into(), Value::Int(99)).unwrap();
    let Some(Value::Object(second)) = core.advance_for_of_iterator(None, entries).unwrap()
    else { panic!("second pair") };
    assert_ne!(first, second);
    assert_eq!(core.heap[source.0 as usize].properties.get("0"), Some(&Value::Int(7)));
    assert_eq!(core.heap[second.0 as usize].properties.get("0"), Some(&Value::Int(1)));
    assert_eq!(core.heap[second.0 as usize].properties.get("1"), Some(&Value::Int(8)));
}

#[test]
fn boxed_string_route_retains_exact_code_units() {
    let module = module();
    let mut core = core(false);
    let text = Value::Str(JsString::from_code_units(&[0x41, 0xd83d, 0xde00, 0xd800]));
    let source = core.generic_array_receiver(&module, BuiltinFunctionKind::ArrayValues,
        false, Some(&text), RegRange { start: 0, count: 0 }).unwrap().expect("boxed receiver");
    let value = iterator(&mut core, &module, source, BuiltinFunctionKind::ArrayValues);
    for unit in [0x41, 0xd83d, 0xde00, 0xd800] {
        assert_eq!(core.advance_for_of_iterator(None, value.clone()).unwrap(),
            Some(Value::Str(JsString::from_code_units(&[unit]))));
    }
    assert_eq!(core.advance_for_of_iterator(None, value).unwrap(), None);
}

#[test]
fn source_lives_through_the_existing_iterator_gc_root() {
    let module = module();
    let mut core = core(false);
    let source = source(&mut core, 1);
    core.set_object_property(source, "0".into(), Value::Int(7)).unwrap();
    let value = iterator(&mut core, &module, source, BuiltinFunctionKind::ArrayValues);
    core.seed_register(0, value.clone()).expect("root iterator only");
    let garbage = core.alloc_object_with_prototype(None).unwrap();
    let previous = core.gc_arm_top_level();
    core.gc_enter_run_loop();
    core.gc_safe_point();
    core.gc_exit_run_loop();
    core.gc_restore_safe_depth(previous);
    assert_eq!(core.gc_stats().collections, 1);
    assert_eq!(core.gc_stats().skipped_collections, 0);
    assert!(core.heap.is_reclaimed(garbage.0 as usize));
    assert!(core.heap.get(source.0 as usize).is_some());
    assert_eq!(core.advance_for_of_iterator(None, value).unwrap(), Some(Value::Int(7)));
}

#[test]
fn iterator_memory_admission_is_not_bypassed_by_lazy_creation() {
    let module = module();
    let mut core = core(false);
    let source = source(&mut core, 1_000_000_000);
    let count = core.iterators.len();
    core.config.max_total_memory_bytes = core.estimated_memory_bytes;
    let outcome = core.array_method_generic(&module, BuiltinFunctionKind::ArrayValues,
        source, RegRange { start: 0, count: 0 });
    assert!(matches!(outcome, Err(InterpreterError::MemoryBudgetExceeded { .. })));
    assert_eq!(core.iterators.len(), count, "refused state must not be published");
}
