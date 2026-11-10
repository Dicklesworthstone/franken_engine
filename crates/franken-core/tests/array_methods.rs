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

#[test]
fn callbacks_receive_live_values_indices_receiver_and_this_arg() {
    assert_output(
        r#"
        const values = [2, 4, 6];
        const context = { offset: 10 };
        const mapped = values.map(function(value, index, array) {
            console.log(array === values);
            return value + index + this.offset;
        }, context);
        console.log(mapped.join(','));
        console.log(values.filter(value => value > 2).join(','));
        let sum = 0;
        console.log(values.forEach(function(value) { sum += value + this.offset; }, context));
        console.log(sum);
        console.log(values.some(value => value === 4));
        console.log(values.every(value => value > 1));
        console.log(values.find(value => value > 3));
        console.log(values.findIndex(value => value > 3));
        console.log(values.find(value => value > 9));
        console.log(values.findIndex(value => value > 9));
        console.log(values.reduce((total, value) => total + value, 10));
        console.log(values.reduceRight((total, value) => total - value));
    "#,
        &[
            "true",
            "true",
            "true",
            "12,15,18",
            "4,6",
            "undefined",
            "42",
            "true",
            "true",
            "4",
            "1",
            "undefined",
            "-1",
            "22",
            "0",
        ],
    );
}

#[test]
fn callback_methods_use_native_async_generator_and_nested_callable_dispatch() {
    assert_output(
        r#"
        console.log([1, [2], 3].filter(Array.isArray).length);
        const totals = [1, 2].map(value => [value, value + 1].reduce((sum, item) => sum + item, 0));
        console.log(totals.join(','));
        function* values(value) { yield value; }
        const generators = [5, 6].map(values);
        console.log(generators[0].next().value);
        console.log(generators[1].next().value);
        const promises = [1, 2].map(async value => value + 1);
        Promise.all(promises).then(items => console.log(items.join(',')));
    "#,
        &["1", "3,5", "5", "6", "2,3"],
    );
}

#[test]
fn callback_methods_preserve_holes_and_observe_inherited_elements() {
    assert_output(
        r#"
        const values = [2, , 6];
        const mapped = values.map(value => value * 2);
        console.log(mapped.length);
        console.log(1 in mapped);
        console.log(mapped.join(','));
        console.log(values.filter(value => true).join(','));
        const parent = { 1: 5, map: [].map, filter: [].filter, reduce: [].reduce };
        values.__proto__ = parent;
        console.log(values.map(value => value * 2).join(','));
        console.log(values.filter(value => true).join(','));
        console.log(values.reduce((total, value) => total + value, 0));
        const generic = {
            length: 3,
            0: 'a',
            get 2() { console.log('get'); return 'c'; },
            map: [].map,
            forEach: [].forEach
        };
        console.log(generic.map((value, index, object) => value + index + (object === generic)).join('|'));
        generic.forEach((value, index) => console.log(index + ':' + value));
    "#,
        &[
            "3",
            "false",
            "4,,12",
            "2,6",
            "4,10,12",
            "2,5,6",
            "13",
            "get",
            "a0true||c2true",
            "0:a",
            "get",
            "2:c",
        ],
    );
}

#[test]
fn callbacks_snapshot_length_but_recheck_presence_and_values_each_time() {
    assert_output(
        r#"
        const values = [1, 2, 3];
        const mapped = values.map(function(value, index, array) {
            console.log(index);
            if (index === 0) { delete array[1]; array[2] = 9; array.push(4); }
            return value * 10;
        });
        console.log(mapped.join(','));
        console.log(mapped.length);
        console.log(values.length);
        const generic = {
            length: 3,
            get 0() { this[1] = 7; delete this[2]; return 2; },
            2: 4,
            filter: [].filter
        };
        console.log(generic.filter(value => true).join(','));
        const selected = [1, 2].find(function(value, index, array) {
            array[index] = 99;
            return true;
        });
        console.log(selected);
    "#,
        &["0", "2", "10,,90", "3", "4", "2,7", "1"],
    );
}

#[test]
fn search_callbacks_visit_holes_and_short_circuit_without_later_getters() {
    assert_output(
        r#"
        const sparse = [, 4];
        console.log(sparse.find(function(value, index) { console.log(index + ':' + value); return true; }));
        console.log(sparse.findIndex(value => value === undefined));
        const object = {
            length: 3,
            0: 2,
            get 1() { throw 'late'; },
            some: [].some,
            every: [].every,
            find: [].find,
            findIndex: [].findIndex
        };
        console.log(object.some(value => value === 2));
        console.log(object.every(value => value === 9));
        console.log(object.find(value => value === 2));
        console.log(object.findIndex(value => value === 2));
        console.log([].some(value => true));
        console.log([].every(value => false));
        console.log([].find(value => true));
        console.log([].findIndex(value => true));
        try { [].map(null); } catch (error) { console.log(error.name); }
        try { [].forEach(1); } catch (error) { console.log(error.name); }
        try { [].reduce(undefined, 0); } catch (error) { console.log(error.name); }
    "#,
        &[
            "0:undefined",
            "undefined",
            "0",
            "true",
            "false",
            "2",
            "0",
            "false",
            "true",
            "undefined",
            "-1",
            "TypeError",
            "TypeError",
            "TypeError",
        ],
    );
}

#[test]
fn reductions_handle_empty_sparse_receivers_and_visit_right_to_left() {
    assert_output(
        r#"
        const values = [, 2, , 5];
        console.log(values.reduce(function(total, value, index, array) {
            console.log(index + ':' + (array === values) + ':' + (this === undefined));
            return total + value;
        }));
        console.log(values.reduceRight(function(total, value, index) {
            console.log(index);
            return total - value;
        }));
        console.log([].reduce((total, value) => total + value, 8));
        console.log([].reduceRight((total, value) => total + value, undefined));
        try { [, ,].reduce((total, value) => total + value); } catch (error) { console.log(error.name); }
        try { [].reduceRight((total, value) => total + value); } catch (error) { console.log(error.name); }
        const generic = {
            length: 4,
            get 3() { console.log('last'); this[1] = 7; return 9; },
            0: 2,
            reduceRight: [].reduceRight
        };
        console.log(generic.reduceRight((total, value) => total - value));
    "#,
        &[
            "3:true:true",
            "7",
            "1",
            "3",
            "8",
            "undefined",
            "TypeError",
            "TypeError",
            "last",
            "0",
        ],
    );
}

#[test]
fn callbacks_and_element_getters_preserve_exact_throws_and_finally_state() {
    assert_output(
        r#"
        const reason = {};
        let calls = 0;
        function run() {
            try {
                [1, 2, 3].map(function(value) { calls++; if (value === 2) throw reason; return value; });
            } finally { console.log('finally'); }
        }
        try { run(); } catch (error) { console.log(error === reason); }
        console.log(calls);
        const object = { length: 1, get 0() { throw reason; }, filter: [].filter };
        try { object.filter(value => true); } catch (error) { console.log(error === reason); }
        try { [1].reduce((total, value) => { throw reason; }, 0); } catch (error) { console.log(error === reason); }
        console.log([3].map(value => value + 1).join());
    "#,
        &["finally", "true", "2", "true", "true", "4"],
    );
}

#[test]
fn map_and_filter_use_species_and_create_own_data_properties() {
    assert_output(
        r#"
        function Result(length) { console.log('construct:' + length); this.length = length; }
        Result.prototype = { set 0(value) { throw 'inherited setter'; } };
        const values = [2, 4];
        const species = { get [Symbol.species]() { console.log('species'); return Result; } };
        values.__proto__ = {
            get constructor() { console.log('constructor'); return species; },
            map: [].map,
            filter: [].filter
        };
        const mapped = values.map(value => { console.log('map:' + value); return value * 3; });
        console.log(mapped[0] + ':' + mapped[1] + ':' + mapped.length);
        const filtered = values.filter(value => value > 2);
        console.log(filtered[0] + ':' + filtered.length);
        try { values.map(0); } catch (error) { console.log(error.name); }
        const normal = [1, 2];
        normal.constructor = { [Symbol.species]: null };
        console.log(normal.map(value => value + 1).join());
        normal.constructor = null;
        try { normal.map(value => value); } catch (error) { console.log(error.name); }
        normal.constructor = { [Symbol.species]: {} };
        try { normal.filter(value => true); } catch (error) { console.log(error.name); }
    "#,
        &[
            "constructor",
            "species",
            "construct:2",
            "map:2",
            "map:4",
            "6:12:2",
            "constructor",
            "species",
            "construct:0",
            "4:0",
            "TypeError",
            "2,3",
            "TypeError",
            "TypeError",
        ],
    );
}

#[test]
fn array_callback_internal_loops_respect_resource_admission() {
    let sparse = lower(
        "const object = { length: 9007199254740991, forEach: [].forEach }; try { object.forEach(value => value); } catch (error) { console.log('caught'); }",
    );
    let growing = lower(
        "const object = { length: 10000, find: [].find }; try { object.find(value => 'abcdefgh'); } catch (error) { console.log('caught'); }",
    );
    for throughput in [false, true] {
        let mut bounded = config(throughput);
        bounded.instruction_budget = 1_000;
        let error = InterpreterCore::new(bounded, "array-callback-step-budget")
            .execute(&sparse)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::BudgetExhausted { .. }),
            "{error:?}"
        );
        let mut denied = config(throughput);
        denied.max_call_depth = 0;
        let error = InterpreterCore::new(denied, "array-callback-call-budget")
            .execute(&growing)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::StackOverflow { .. }),
            "{error:?}"
        );
    }
    assert_output(
        "const object = { length: 4294967296, map: [].map }; try { object.map(value => { console.log('called'); return value; }); } catch (error) { console.log(error.name); }",
        &["RangeError"],
    );
}

#[test]
fn callback_array_results_retain_element_and_predicate_provenance() {
    for throughput in [false, true] {
        for (method, callback_source) in [
            ("map", "value => value"),
            ("filter", "value => true"),
            ("find", "value => true"),
            ("some", "value => true"),
            ("reduce", "(accumulator, value) => 1"),
        ] {
            let mut core = InterpreterCore::new(config(throughput), "array-callback-labels");
            let setup = format!(
                "const holder = {{ values: [42, 43], callback: {callback_source} }}; holder;"
            );
            let Value::Object(holder) = core.execute(&lower(&setup)).unwrap().value else {
                panic!("callback holder completion")
            };
            let holder = &core.get_heap()[holder.0 as usize];
            let callback = holder.properties.get("callback").unwrap().clone();
            let array = holder.properties.get("values").unwrap().clone();
            let Value::Object(object) = array else {
                panic!("array completion")
            };
            core.write_register(0, Value::Object(object));
            core.write_register(1, Value::str(method));
            core.write_register(2, callback);
            let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
            wire["heap"][object.0 as usize]["property_labels"]["0"] =
                serde_json::to_value(Label::Secret).unwrap();
            core.reset_execution_state_from_seed(
                &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
            )
            .unwrap();
            let result = core.execute(&native_array_call(1)).unwrap();
            assert_eq!(result.completion_label, Label::Secret, "{method}");
            if let Value::Object(result_object) = result.value {
                let object =
                    serde_json::to_value(&core.get_heap()[result_object.0 as usize]).unwrap();
                assert_eq!(
                    object["property_labels"]["0"],
                    serde_json::to_value(Label::Secret).unwrap(),
                    "{method}",
                );
            }
        }
    }
}

#[test]
fn array_callback_validation_errors_keep_secret_dependencies_in_catch() {
    for throughput in [false, true] {
        for secret_length in [false, true] {
            let mut core = InterpreterCore::new(config(throughput), "array-callback-error-label");
            let source = if secret_length {
                "const value = { length: Symbol('length'), map: [].map }; value;"
            } else {
                "const value = [1]; value;"
            };
            let Value::Object(object) = core.execute(&lower(source)).unwrap().value else {
                panic!("array-like completion")
            };
            core.write_register(0, Value::Object(object));
            core.write_register(1, Value::str("map"));
            core.write_register(2, Value::Int(7));
            let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
            if secret_length {
                wire["heap"][object.0 as usize]["property_labels"]["length"] =
                    serde_json::to_value(Label::Secret).unwrap();
            } else {
                wire["register_labels"][2] = serde_json::to_value(Label::Secret).unwrap();
            }
            core.reset_execution_state_from_seed(
                &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
            )
            .unwrap();
            let mut module = native_array_call(1);
            module.instructions.insert(
                0,
                Op::BeginTry {
                    catch_target: 5,
                    finally_target: None,
                },
            );
            module.instructions.insert(3, Op::EndTry);
            module.instructions.push(Op::EnterCatch { dst: 7 });
            module.instructions.push(Op::Return { value: 7 });
            let result = core.execute(&module).unwrap();
            assert_eq!(result.completion_label, Label::Secret);
            let Value::Object(error) = result.value else {
                panic!("caught TypeError object")
            };
            assert_eq!(
                core.get_heap()[error.0 as usize].properties.get("name"),
                Some(&Value::str("TypeError")),
            );
        }
    }
}
