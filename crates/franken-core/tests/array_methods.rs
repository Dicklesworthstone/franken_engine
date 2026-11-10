//! Real array methods through ordinary property lookup in both core profiles.

use std::collections::BTreeSet;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionSeed, InterpreterConfig, InterpreterCore, InterpreterError, ObjectId, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{Ir0Module, Ir3Instruction as Op, Ir3Module, RegRange};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .expect("parse array method source");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "array-methods.mjs"),
        &LoweringContext::new("array-methods", "array-methods", "array-methods"),
    )
    .expect("lower array method source")
    .ir3
}

fn config(throughput: bool) -> InterpreterConfig {
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for throughput in [false, true] {
        let result = InterpreterCore::new(config(throughput), "array-methods")
            .execute(&module)
            .expect("execute array method source");
        let actual: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(actual, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn push_pop_and_join_use_current_length_and_preserve_values() {
    assert_output(
        r#"
        const values = [];
        console.log(values.length);
        console.log(values.push(3, null, undefined, 7));
        console.log(values.length);
        console.log(values.join());
        console.log(values.join('|'));
        console.log(values.pop());
        console.log(values.length);
        console.log(values.pop());
        console.log(values.pop());
        console.log(values.pop());
        console.log(values.pop());
        console.log(values.length);
        console.log(values.join('-'));
        const sparse = [1, , 3];
        console.log(sparse.push(4));
        console.log(sparse.join(':'));
        function literal() { return [5, 6]; }
        const returned = literal();
        console.log(returned.join('-'));
        returned[4] = 9;
        console.log(returned.length);
        console.log(returned.join(':'));
        const numericLength = [];
        numericLength.length = 10.0;
        numericLength[5] = 1;
        numericLength['05'] = 2;
        numericLength[4294967295] = 3;
        console.log(numericLength.length);
        console.log(numericLength.join('|'));
        Promise.all(returned).then(items => console.log(items.length + ':' + items[4]));
    "#,
        &[
            "0",
            "4",
            "4",
            "3,,,7",
            "3|||7",
            "7",
            "3",
            "undefined",
            "null",
            "3",
            "undefined",
            "0",
            "",
            "4",
            "1::3:4",
            "5-6",
            "5",
            "5:6:::9",
            "10",
            "|||||1||||",
            "5:9",
        ],
    );
}

#[test]
fn join_snapshots_length_but_reads_live_elements_after_separator_conversion() {
    assert_output(
        r#"
        const values = [1, 2];
        const separator = { toString() { values.push(3); values[1] = 9; return '|'; } };
        console.log(values.join(separator));
        console.log(values.length);
        const object = {
            length: 3,
            join: [].join,
            get 0() { console.log('first'); this[1] = 'updated'; this.length = 1; return 'a'; },
            1: 'old',
            get 2() { console.log('last'); return 'c'; }
        };
        console.log(object.join('-'));
        console.log(object.length);
    "#,
        &["1|9", "3", "first", "last", "a-updated-c", "1"],
    );
}

#[test]
fn methods_are_borrowable_and_use_accessors_on_the_actual_receiver() {
    assert_output(
        r#"
        const object = {
            size: 1,
            0: 'a',
            get length() { console.log('length'); return this.size; },
            set length(value) { console.log('size:' + value); this.size = value; },
            get 1() { return this.saved; },
            set 1(value) { console.log('one:' + value); this.saved = value; },
            push: [].push,
            pop: [].pop,
            join: [].join
        };
        console.log(object.push('b'));
        console.log(object.join('-'));
        console.log(object.pop());
        console.log(object.join('-'));
    "#,
        &[
            "length", "one:b", "size:2", "2", "length", "a-b", "length", "size:1", "b", "length",
            "a",
        ],
    );
}

#[test]
fn property_overrides_and_custom_prototypes_precede_intrinsic_methods() {
    assert_output(
        r#"
        const values = [1];
        values.push = function(value) { console.log(this === values); return value + 40; };
        console.log(values.push(2));
        console.log(values.length);
        delete values.push;
        console.log(values.push(2));
        values.join = undefined;
        try { values.join(); } catch (error) { console.log(error.name); }
        const missing = values.join;
        try { missing(); } catch (error) { console.log(error.name); }
        delete values.join;
        console.log(values.join('-'));
        const nativePush = values.push;
        const parent = { get push() { console.log(this === values); return nativePush; } };
        values.__proto__ = parent;
        console.log(values.push(3));
        console.log(values.length);
        console.log(typeof values.join);
        values.__proto__ = null;
        console.log(typeof values.push);
    "#,
        &[
            "true",
            "42",
            "1",
            "2",
            "TypeError",
            "TypeError",
            "1-2",
            "true",
            "3",
            "3",
            "undefined",
            "undefined",
        ],
    );
}

#[test]
fn method_lookup_and_arguments_evaluate_once_and_detached_calls_have_no_receiver() {
    assert_output(
        r#"
        const values = [];
        function receiver() { console.log('receiver'); return values; }
        function key() { console.log('key'); return 'push'; }
        function argument() { console.log('argument'); return 5; }
        console.log(receiver()[key()](argument()));
        console.log(values[0]);
        const detached = values.push;
        try { detached(9); } catch (error) { console.log(error.name); }
        console.log(values.length);
        const other = { length: 0, push: detached };
        console.log(other.push(11));
        console.log(other[0]);
        console.log(values.length);
    "#,
        &[
            "receiver",
            "key",
            "argument",
            "1",
            "5",
            "TypeError",
            "1",
            "1",
            "11",
            "1",
        ],
    );
}

#[test]
fn join_performs_exact_primitive_conversion_and_bounds_cycles() {
    assert_output(
        r#"
        const element = { [Symbol.toPrimitive](hint) { console.log(hint); return 42; } };
        console.log([element, {}, [1, 2], null, undefined].join('|'));
        const nested = [3, 4];
        nested.join = function() { console.log(this === nested); return 'custom'; };
        console.log([nested].join());
        const cycle = [1];
        cycle.push(cycle);
        console.log(cycle.join('|'));
        console.log(['\uD800', '\uDC00'].join('') === '\uD800\uDC00');
        console.log(['\uD800'].join('|') === '\uD800');
        try { [Symbol('x')].join(); } catch (error) { console.log(error.name); }
        try { [1].join(Symbol('separator')); } catch (error) { console.log(error.name); }
        const noJoin = [];
        noJoin.join = 1;
        console.log([noJoin].join());
        const nullPrototype = [1];
        nullPrototype.__proto__ = null;
        try { [nullPrototype].join(); } catch (error) { console.log(error.name); }
        const customPrototype = [1];
        customPrototype.__proto__ = { join() { return 'ignored'; } };
        console.log([customPrototype].join());
    "#,
        &[
            "string",
            "42|[object Object]|1,2||",
            "true",
            "custom",
            "1|",
            "true",
            "true",
            "TypeError",
            "TypeError",
            "[object Array]",
            "TypeError",
            "[object Array]",
        ],
    );
}

#[test]
fn generic_lengths_coerce_once_and_range_errors_precede_push_mutation() {
    assert_output(
        r#"
        const object = { length: { valueOf() { console.log('length'); return 2.9; } }, 0: 'a', 1: 'b', join: [].join };
        console.log(object.join(null));
        const negative = { length: -1, push: [].push };
        console.log(negative.push(7));
        console.log(negative[0]);
        const huge = { length: 9007199254740991, push: [].push };
        try { huge.push(1); } catch (error) { console.log(error.name); }
        console.log(huge.length);
        console.log(huge[9007199254740991]);
    "#,
        &[
            "length",
            "anullb",
            "1",
            "7",
            "TypeError",
            "9007199254740991",
            "undefined",
        ],
    );
}

#[test]
fn accessor_failures_keep_exact_thrown_values_and_prevent_later_writes() {
    assert_output(
        r#"
        const reason = {};
        const object = { length: 1, get 0() { throw reason; }, pop: [].pop };
        try { object.pop(); } catch (error) { console.log(error === reason); }
        console.log(object.length);
        const readonly = { get length() { return 0; }, push: [].push };
        try { readonly.push(8); } catch (error) { console.log(error.name); }
        console.log(readonly[0]);
        console.log(readonly.length);
        const partial = [];
        const push = partial.push;
        partial.__proto__ = { push, set 1(value) { console.log(this.length); throw value; } };
        try { partial.push(1, 2); } catch (error) { console.log(error); }
        console.log(partial.length);
        console.log(partial[0]);
    "#,
        &["true", "1", "TypeError", "8", "0", "1", "2", "1", "1"],
    );
}

#[test]
fn native_join_loop_cannot_escape_instruction_budget_through_guest_catch() {
    let module = lower(
        "const value = { length: 9007199254740991, join: [].join }; try { value.join(''); } catch (error) { console.log('caught'); }",
    );
    for throughput in [false, true] {
        let mut config = config(throughput);
        config.instruction_budget = 1_000;
        let error = InterpreterCore::new(config, "array-method-budget")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::BudgetExhausted { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn join_checks_string_admission_even_when_each_input_fits() {
    let module = lower(
        "try { ['abcdefgh', 'abcdefgh', 'abcdefgh'].join('-'); } catch (error) { console.log('caught'); }",
    );
    for throughput in [false, true] {
        let mut config = config(throughput);
        config.max_string_size = 16;
        let error = InterpreterCore::new(config, "array-method-string-budget")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::StringLimitExceeded { .. }),
            "{error:?}"
        );
    }
}

fn native_array_call(argument_count: u32) -> Ir3Module {
    let mut module = Ir3Module::new(
        ContentHash::compute(b"array-native-call"),
        "array-native-call",
    );
    module.instructions = vec![
        Op::GetProperty {
            dst: 3,
            obj: 0,
            key: 1,
        },
        Op::CallMethod {
            dst: 4,
            callee: 3,
            receiver: 0,
            args: RegRange {
                start: 2,
                count: argument_count,
            },
        },
        Op::Return { value: 4 },
    ];
    module
}

#[test]
fn array_methods_preserve_element_and_receiver_provenance() {
    for throughput in [false, true] {
        let mut core = InterpreterCore::new(config(throughput), "array-method-labels");
        core.execute(&lower("const values = [1];")).unwrap();
        let index = core
            .get_heap()
            .iter()
            .position(|object| object.is_array)
            .unwrap();
        core.write_register(0, Value::Object(ObjectId(index as u32)));
        core.write_register(1, Value::str("push"));
        core.write_register(2, Value::Int(42));
        let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
        wire["register_labels"][2] = serde_json::to_value(Label::Secret).unwrap();
        core.reset_execution_state_from_seed(
            &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
        )
        .unwrap();
        let result = core.execute(&native_array_call(1)).unwrap();
        assert_eq!(result.value, Value::Int(2));
        let object = serde_json::to_value(&core.get_heap()[index]).unwrap();
        assert_eq!(
            object["property_labels"]["1"],
            serde_json::to_value(Label::Secret).unwrap()
        );
        core.write_register(0, Value::Object(ObjectId(index as u32)));
        core.write_register(1, Value::str("join"));
        let result = core.execute(&native_array_call(0)).unwrap();
        assert_eq!(result.value, Value::str("1,42"));
        assert_eq!(result.completion_label, Label::Secret);
    }
}

#[test]
fn explicit_null_array_prototypes_survive_seeds_without_contaminating_new_arrays() {
    let mut core = InterpreterCore::new(config(false), "array-null-seed");
    let empty = core.capture_execution_seed();
    core.execute(&lower("const values = []; values.__proto__ = null;"))
        .unwrap();
    let index = core
        .get_heap()
        .iter()
        .position(|object| object.is_array)
        .unwrap();
    core.write_register(0, Value::Object(ObjectId(index as u32)));
    core.write_register(1, Value::str("push"));
    let seed: ExecutionSeed =
        serde_json::from_value(serde_json::to_value(core.capture_execution_seed()).unwrap())
            .unwrap();
    let mut lookup = Ir3Module::new(
        ContentHash::compute(b"array-null-lookup"),
        "array-null-lookup",
    );
    lookup.instructions = vec![
        Op::GetProperty {
            dst: 2,
            obj: 0,
            key: 1,
        },
        Op::Return { value: 2 },
    ];
    let mut restored = InterpreterCore::new(config(false), "restored-array-null-seed");
    restored.reset_execution_state_from_seed(&seed).unwrap();
    assert_eq!(restored.execute(&lookup).unwrap().value, Value::Undefined);
    core.reset_execution_state_from_seed(&empty).unwrap();
    let result = core
        .execute(&lower("const values = []; console.log(values.push(42));"))
        .unwrap();
    assert_eq!(result.console_output[0].message, "1");

    let mut invalid = restored.capture_execution_seed_eager_for_test();
    invalid.heap.clear();
    assert!(
        restored
            .reset_execution_state_from_seed_eager_for_test(&invalid)
            .is_err()
    );
}

#[test]
fn retained_join_output_is_charged_to_memory_budget() {
    for throughput in [false, true] {
        let mut config = config(throughput);
        config.max_total_memory_bytes = 65_536;
        let mut core = InterpreterCore::new(config.clone(), "small-array-join");
        core.execute(&lower(
            "const values = { length: 8, join: [].join }; console.log(values.join());",
        ))
        .unwrap();
        let error = InterpreterCore::new(config, "large-array-join")
            .execute(&lower("const values = { length: 100000, join: [].join }; try { values.join(); } catch (error) { console.log('caught'); }"))
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::MemoryBudgetExceeded { .. }),
            "{error:?}"
        );
    }
}
