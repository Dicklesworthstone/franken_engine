//! Spreading generators and iterating Map/Set (reality check 2026-09-23).
//!
//! `[...g()]` failed with "expected iterable, got object" (array spread had no
//! arm for generator objects), and `for (const [k, v] of map)`, `[...set]` and
//! friends failed with "expected callable Symbol.iterator method" (collections
//! exposed no iteration). Expected strings are what Node v22.2.0 prints.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::flow_lattice::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

/// Map.prototype, Set.prototype and String.prototype hold their @@iterator
/// (Map's is `entries`, Set's `values`); only instances and primitives had
/// it, so `typeof Map.prototype[Symbol.iterator]` was "undefined" (Test262
/// String/prototype/Symbol.iterator/name and relatives).
#[test]
fn collection_and_string_prototypes_have_their_iterator() {
    check(
        "[typeof String.prototype[Symbol.iterator], typeof Map.prototype[Symbol.iterator], \
         typeof Set.prototype[Symbol.iterator], \
         Map.prototype[Symbol.iterator] === Map.prototype.entries, \
         Set.prototype[Symbol.iterator] === Set.prototype.values, \
         Map.prototype[Symbol.iterator] === new Map()[Symbol.iterator], \
         [...String.prototype[Symbol.iterator].call('ab')].join(), \
         [...Map.prototype[Symbol.iterator].call(new Map([[1, 2]]))].join(), \
         Symbol.iterator in Map.prototype].join(' ')",
        "function function function true true true a,b 1,2 true",
    );
}

#[test]
fn generator_objects_spread_into_arrays() {
    check(
        "function* g() { yield 1; yield 2; } [...g()].join();",
        "1,2",
    );
    check(
        "function* g() { yield* [1, 2]; yield 3; } [...g()].join();",
        "1,2,3",
    );
    check("function* g() {} [...g()].length;", "0");
    check(
        "function* g() { yield 'b'; } ['a', ...g(), 'c'].join('');",
        "abc",
    );
}

#[test]
fn map_iterates_entries_in_insertion_order() {
    check(
        "const m = new Map(); m.set('b', 1); m.set('a', 2); m.set(3, 'x'); \
         let out = []; for (const [k, v] of m) out.push(k + '=' + v); out.join(',');",
        "b=1,a=2,3=x",
    );
    check(
        "const m = new Map([['k', 1]]); m.set('k', 5); [...m].map(e => e.join(':')).join();",
        "k:5",
    );
    check(
        "const o = {}; const m = new Map(); m.set(o, 1); let hit = false; \
         for (const [k] of m) hit = k === o; hit;",
        "true",
    );
}

/// A regex literal right after a spread's `...` was read as a division by the
/// statement scanner ("empty expression statement").
#[test]
fn a_regex_literal_can_follow_a_spread() {
    check(
        "[[.../ab/.exec('xab')].join(), [...'q', .../c(d)/.exec('cd')].join(), \
         (function () { return [...arguments, .../z/g.exec('z')].length; })(1, 2)].join(' ');",
        "ab q,cd,d 3",
    );
}

#[test]
fn set_iterates_values_in_insertion_order() {
    check("[...new Set([3, 1, 3, 2])].join();", "3,1,2");
    check(
        "let t = 0; for (const v of new Set([1, 2, 2, 3])) t += v; t;",
        "6",
    );
}

/// An arguments object has an own, non-enumerable @@iterator that is
/// %Array.prototype.values% (ES2020 9.4.4.6), so it spreads, converts and
/// iterates like an array. It had none: `[...arguments]` threw "expected
/// callable Symbol.iterator method".
#[test]
fn arguments_objects_are_iterable() {
    check(
        "(function () { let s = ''; for (const a of arguments) s += a; \
         return [[...arguments].join(), Array.from(arguments).length, s, \
         JSON.stringify(Object.keys(arguments)), arguments[Symbol.iterator] === Array.prototype.values, \
         Object.getOwnPropertyDescriptor(arguments, Symbol.iterator).enumerable, \
         [...arguments, .../z/g.exec('z')].length].join(' '); })(1, 2);",
        r#"1,2 2 12 ["0","1"] true false 3"#,
    );
}

/// Map, Set, WeakMap and WeakSet seed from any iterable through the
/// iteration protocol (ES2020 23.1.1.1ff.): another collection, a generator,
/// a `keys()`/`values()` iterator, a user iterable, a string, an array with
/// holes. A Map entry is any object (`Get(entry, "0")`, `Get(entry, "1")`),
/// and a non-iterable, a non-object entry or a value that cannot be weakly
/// held is a TypeError. Seeding read indexed properties instead, so
/// `new Map(otherMap)`, `new Set(generator())` and `new Set(map.keys())`
/// were silently empty and the errors were skipped.
#[test]
fn collections_seed_from_any_iterable() {
    check(
        "function* g() { yield ['k', 'v']; yield ['k2', 'v2']; } \
         var m = new Map([[1, 'a'], [2, 'b']]); \
         var it = { [Symbol.iterator]() { var i = 0; return { next() { \
         return i++ < 2 ? { value: [i, i * 10], done: false } : { done: true }; } }; } }; \
         var holes = [1, 2]; holes[5] = 6; \
         [new Map(m).get(2), new Set(new Set([1, 2])).size, new Map(g()).get('k2'), \
         new Set(m.keys()).size, [...new Set(m.values())].join(''), new Map([[1, 2]].values()).get(1), \
         new Map(it).get(2), new Map([{ 0: 'a', 1: 'b' }]).get('a'), new Set('abca').size, \
         new Set(holes).size, new Map(undefined).size, new Set(null).size].join();",
        "b,2,v2,2,ab,2,20,b,3,4,0,0",
    );
    check(
        "function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } } \
         var k = {}; var fn = function () {}; \
         [attempt(() => new Map(5)), attempt(() => new Set({ length: 2, 0: 'a' })), \
         attempt(() => new Map(['ab'])), attempt(() => new Map([1])), \
         attempt(() => new WeakMap([[1, 'x']])), attempt(() => new WeakMap([1])), \
         attempt(() => new WeakSet([1])), new WeakSet(new Set([k])).has(k), \
         new WeakMap(new Map([[k, 1], [fn, 2]])).get(fn), new WeakSet([fn]).has(fn)].join();",
        "TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,true,2,true",
    );
    // A failed WeakMap seed keeps what the program's iterator allocated.
    check(
        "function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } } \
         var saved; var leaky = { [Symbol.iterator]() { return { next() { \
         saved = { kept: true }; return { value: 1, done: false }; } }; } }; \
         [attempt(() => new WeakMap(leaky)), saved.kept, JSON.stringify(saved)].join(' ');",
        r#"TypeError true {"kept":true}"#,
    );
}

#[test]
fn collection_constructors_read_array_seeds_live_and_in_order() {
    check(
        r#"
const order = [];
const entries = [{
    get 0() {
        order.push('key');
        entries[1] = ['changed', 2];
        entries.push(['appended', 3]);
        return 'first';
    },
    get 1() { order.push('value'); return 1; }
}, ['old', 0]];
const map = new Map(entries);
const ordered = [{ get 0() { order.push('entry'); return 'k'; }, 1: 7 }];
Object.defineProperty(ordered, '1', {
    get() { order.push('index'); return ['later', 8]; }, configurable: true
});
new Map(ordered);
[map.get('first'), map.get('changed'), map.get('appended'), map.has('old'),
 order.join(':')].join('|');
"#,
        "1|2|3|false|key:value:entry:index",
    );
    check(
        r#"
const source = [1, 2];
class LiveSet extends Set {
    add(value) {
        if (value === 1) { source[1] = 3; source.push(4); }
        return super.add(value);
    }
}
const set = new LiveSet(source);
const keys = [{}, {}, {}];
const pairs = [{
    get 0() { pairs[1] = [keys[2], 9]; return keys[0]; }, 1: 7
}, [keys[1], 8]];
const weak = new WeakMap(pairs);
[[...set].join(), weak.get(keys[0]), weak.has(keys[1]), weak.get(keys[2])].join('|');
"#,
        "1,3,4|7|false|9",
    );
}

#[test]
fn invalid_array_entry_stops_before_later_index_getters() {
    check(
        r#"
const entries = [1];
let later = 0;
Object.defineProperty(entries, '1', { get() { later++; return ['k', 2]; } });
let error = '';
try { new Map(entries); } catch (caught) { error = caught.name; }
[error, later].join('|');
"#,
        "TypeError|0",
    );
}

#[test]
fn map_entries_can_be_callable_or_exotic_objects() {
    check(
        r#"
const key = {};
function entry() {}
entry[0] = 'callable';
entry[1] = 7;
const exotic = Promise.resolve();
exotic[0] = 'promise';
exotic[1] = 8;
const map = new Map([entry, exotic]);
entry[0] = key;
exotic[0] = key;
const weak = new WeakMap([entry, exotic]);
[map.get('callable'), map.get('promise'), map.has(undefined), weak.get(key)].join('|');
"#,
        "7|8|false|8",
    );
}

#[test]
fn weakmap_seed_insertions_are_visible_before_later_entries_and_survive_a_throw() {
    check(
        r#"
const intrinsic = WeakMap.prototype.set;
const key = {};
let exposed;
let observed;
let closed = 0;
Object.defineProperty(WeakMap.prototype, 'set', {
    get() { exposed = this; return intrinsic; }, configurable: true
});
function* entries() {
    try {
        yield [key, 7];
        yield { get 0() { observed = exposed.get(key); return key; }, 1: 9 };
        yield null;
    } finally { closed++; }
}
let error = '';
try { new WeakMap(entries()); } catch (caught) { error = caught.name; }
[observed, exposed.get(key), error, closed].join('|');
"#,
        "7|9|TypeError|1",
    );
}

fn constructor_configurations() -> [InterpreterConfig; 2] {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .map(|mut config| {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        config
    })
}

fn lower_constructor_source(source: &str) -> Ir3Module {
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(
            parse_script(source).expect("constructor source parses"),
            "collection-constructor.js",
        ),
        &LoweringContext::new("collections", "constructors", "builtin-only"),
    )
    .expect("constructor source lowers")
    .ir3
}

#[test]
fn native_collection_seeds_cannot_bypass_the_instruction_budget() {
    for constructor in ["Map", "Set", "WeakMap", "WeakSet"] {
        let mut module = lower_constructor_source("undefined;");
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag(format!("builtin:{constructor}")),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ];
        for mut config in constructor_configurations() {
            config.instruction_budget = 128;
            for count in [1, 1024] {
                let mut core = InterpreterCore::new(config.clone(), "collection-native-budget");
                let key = core.alloc_object_with_prototype(None).unwrap();
                let entry = if matches!(constructor, "Map" | "WeakMap") {
                    let pair = core.alloc_array_with_prototype(None).unwrap();
                    core.set_object_property(pair, "0".into(), Value::Object(key))
                        .unwrap();
                    core.set_object_property(pair, "1".into(), Value::Int(7))
                        .unwrap();
                    Value::Object(pair)
                } else {
                    Value::Object(key)
                };
                // Preallocated repeated entries keep collection size constant;
                // only the constructor's native work should exhaust the budget.
                let source = core.alloc_array_with_prototype(None).unwrap();
                for index in 0..count {
                    core.set_object_property(source, index.to_string(), entry.clone())
                        .unwrap();
                }
                core.set_object_property(source, "length".into(), Value::Int(count))
                    .unwrap();
                core.seed_register(0, Value::Object(source)).unwrap();
                let result = core.execute(&module);
                if count == 1 {
                    assert!(result.is_ok(), "{constructor}: {result:?}");
                } else {
                    assert!(
                        matches!(result, Err(InterpreterError::BudgetExhausted { .. })),
                        "{constructor}: {result:?}"
                    );
                }
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "{constructor}, count={count}"
                );
            }
        }
    }
}

fn labelled_constructor_module(source: &str, input_register: u32) -> Ir3Module {
    let mut module = lower_constructor_source(source);
    replace_constructor_marker(&mut module, "label-marker", input_register);
    module
}

fn replace_constructor_marker(module: &mut Ir3Module, marker: &str, input_register: u32) {
    let marker = module
        .constant_pool
        .iter()
        .position(|text| text == marker)
        .expect("labelled source marker") as u32;
    let mut replaced = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = instruction
            && *pool_index == marker
        {
            *instruction = Ir3Instruction::Move {
                dst: *dst,
                src: input_register,
            };
            replaced += 1;
        }
    }
    assert_eq!(replaced, 1);
}

#[test]
fn collection_callbacks_preserve_earlier_entry_provenance() {
    for subclass in [false, true] {
        let source = format!(
            r#"
const sensitive = 'label-marker';
class CustomMap extends Map {{ set(key, value) {{ return super.set(key, value); }} }}
const first = {{ get 0() {{ return sensitive; }}, get 1() {{ return Math.abs(-7); }} }};
const second = {{ get 0() {{ return String('public'); }}, get 1() {{ return Math.abs(-9); }} }};
new {}([first, second]);
"#,
            if subclass { "CustomMap" } else { "Map" }
        );
        for config in constructor_configurations() {
            let input_register = config.max_registers - 1;
            let module = labelled_constructor_module(&source, input_register);
            for stress in [None, Some(1), Some(7)] {
                let mut core = InterpreterCore::new(config.clone(), "collection-provenance");
                core.set_gc_stress_interval(stress);
                core.seed_register(input_register, Value::str("private-key"))
                    .unwrap();
                core.set_register_label(input_register, Label::Secret)
                    .unwrap();
                let result = core.execute(&module).expect("collection seed executes");
                assert_eq!(result.completion_label, Label::Secret);
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}

#[test]
fn later_collection_callbacks_cannot_exfiltrate_observed_secrets() {
    for source in [
        r#"
const sensitive = 'label-marker';
const log = console.log;
new Map([{ get 0() { return sensitive; }, get 1() { log('observed'); return 7; } }]);
"#,
        r#"
const sensitive = 'label-marker';
const log = console.log;
const source = [0, 1];
Object.defineProperty(source, '0', { get() { return sensitive; } });
Object.defineProperty(source, '1', { get() { log('observed'); return 7; } });
new Set(source);
"#,
    ] {
        for config in constructor_configurations() {
            let input_register = config.max_registers - 1;
            let module = labelled_constructor_module(source, input_register);
            let mut core = InterpreterCore::new(config, "collection-observation");
            core.seed_register(input_register, Value::str("private-key"))
                .unwrap();
            core.set_register_label(input_register, Label::Secret)
                .unwrap();
            assert!(matches!(
                core.execute(&module),
                Err(InterpreterError::CapabilityDenied { .. })
            ));
            assert!(core.console_output().is_empty());
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn exposed_collection_prefixes_retain_labels_after_failed_construction() {
    for (constructor, method, pairs) in [
        ("Map", "get", true),
        ("Map", "has", true),
        ("WeakMap", "get", true),
        ("WeakMap", "has", true),
        ("Set", "has", false),
        ("WeakSet", "has", false),
    ] {
        let adder = if pairs { "set" } else { "add" };
        let yielded = if pairs {
            "{ 0: key, get 1() { return sensitive; } }"
        } else {
            "(sensitive === 'private-value' ? key : key)"
        };
        let completion = "console.log('public-control'); read.call(exposed, key);";
        let source = format!(
            r#"
const sensitive = 'label-marker';
const key = 'key-marker';
const original = {constructor}.prototype.{adder};
const read = {constructor}.prototype.{method};
let exposed;
Object.defineProperty({constructor}.prototype, '{adder}', {{
    get() {{ exposed = this; return original; }}, configurable: true
}});
function* entries() {{ yield {yielded}; throw new Error('stop'); }}
try {{ new {constructor}(entries()); }} catch (error) {{}}
{completion}
"#
        );
        for config in constructor_configurations() {
            let alias_register = config.max_registers - 1;
            let key_register = alias_register - 1;
            let mut construct = labelled_constructor_module(&source, alias_register);
            replace_constructor_marker(&mut construct, "key-marker", key_register);
            for label in [Label::Public, Label::Secret] {
                let mut core = InterpreterCore::new(config.clone(), "collection-retained-prefix");
                let key = core.alloc_object_with_prototype(None).unwrap();
                core.seed_register(key_register, Value::Object(key))
                    .unwrap();
                core.seed_register(alias_register, Value::str("private-value"))
                    .unwrap();
                core.set_register_label(alias_register, label.clone())
                    .unwrap();
                let result = core
                    .execute(&construct)
                    .expect("construction failure is caught");
                // This public sink proves the catch PC and the seed's
                // callback scope have rejoined before the cached read
                // observes the collection through its preexisting alias.
                assert_eq!(core.console_output().len(), 1);
                assert_eq!(core.console_output()[0].message, "public-control");
                let expected = if method == "get" {
                    Value::str("private-value")
                } else {
                    Value::Bool(true)
                };
                assert_eq!(result.value, expected, "{constructor}.{method}");
                assert_eq!(result.completion_label, label, "{constructor}.{method}");
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "{constructor}.{method}"
                );
            }
        }
    }
}

#[test]
fn empty_collection_iteration_retains_the_constructor_done_observation() {
    for constructor in ["Map", "Set"] {
        let adder = if constructor == "Map" { "set" } else { "add" };
        let source = format!(
            r#"
const done = 'label-marker';
const original = {constructor}.prototype.{adder};
const values = {constructor}.prototype.values;
let exposed;
Object.defineProperty({constructor}.prototype, '{adder}', {{
    get() {{ exposed = this; return original; }}, configurable: true
}});
const source = {{ [Symbol.iterator]() {{ return {{ next() {{ return {{ done }}; }} }}; }} }};
new {constructor}(source);
console.log('public-control');
values.call(exposed).next().done;
"#
        );
        for config in constructor_configurations() {
            let alias_register = config.max_registers - 1;
            let construct = labelled_constructor_module(&source, alias_register);
            for label in [Label::Public, Label::Secret] {
                let mut core = InterpreterCore::new(config.clone(), "empty-collection-observation");
                core.seed_register(alias_register, Value::Bool(true))
                    .unwrap();
                core.set_register_label(alias_register, label.clone())
                    .unwrap();
                let result = core.execute(&construct).expect("empty iteration succeeds");
                assert_eq!(core.console_output().len(), 1);
                assert_eq!(core.console_output()[0].message, "public-control");
                assert_eq!(result.value, Value::Bool(true), "{constructor}");
                assert_eq!(result.completion_label, label, "{constructor}");
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}

#[test]
fn direct_and_borrowed_collection_writes_label_preexisting_aliases() {
    for constructor in ["Map", "Set", "WeakMap"] {
        let pairs = constructor != "Set";
        let adder = if pairs { "set" } else { "add" };
        let method = if pairs { "get" } else { "has" };
        let arguments = if pairs { "key, sensitive" } else { "sensitive" };
        for borrowed in [false, true] {
            let write = if borrowed {
                format!(
                    "const write = {constructor}.prototype.{adder}; \
                     write.call(collection, {arguments});"
                )
            } else {
                format!("collection.{adder}({arguments});")
            };
            let completion = "console.log('public-control'); read.call(alias, key);";
            let source = format!(
                "const sensitive = 'label-marker'; const key = 'key-marker'; \
                 const collection = new {constructor}(); const alias = collection; \
                 const read = {constructor}.prototype.{method}; {write} {completion}"
            );
            for config in constructor_configurations() {
                let alias_register = config.max_registers - 1;
                let key_register = alias_register - 1;
                let mut write = labelled_constructor_module(&source, alias_register);
                replace_constructor_marker(&mut write, "key-marker", key_register);
                for label in [Label::Public, Label::Secret] {
                    let mut core = InterpreterCore::new(config.clone(), "collection-alias-write");
                    let key = core.alloc_object_with_prototype(None).unwrap();
                    core.seed_register(key_register, Value::Object(key))
                        .unwrap();
                    let value = if pairs {
                        Value::str("private-value")
                    } else {
                        Value::Object(key)
                    };
                    core.seed_register(alias_register, value).unwrap();
                    core.set_register_label(alias_register, label.clone())
                        .unwrap();
                    let result = core.execute(&write).expect("collection write succeeds");
                    assert_eq!(core.console_output().len(), 1);
                    assert_eq!(core.console_output()[0].message, "public-control");
                    assert_eq!(
                        result.value,
                        if pairs {
                            Value::str("private-value")
                        } else {
                            Value::Bool(true)
                        },
                        "{constructor}, borrowed={borrowed}"
                    );
                    assert_eq!(
                        result.completion_label, label,
                        "{constructor}, borrowed={borrowed}"
                    );
                    assert_eq!(
                        core.estimated_memory_bytes(),
                        core.recompute_estimated_memory_bytes()
                    );
                }
            }
        }
    }
}

#[test]
fn classified_iterable_selection_constrains_native_constructor_callbacks() {
    for (capability, operation) in [
        ("builtin:Map", "new Map(selected)"),
        ("builtin:Set", "new Set(selected)"),
        ("builtin:WeakMap", "new WeakMap(selected)"),
        ("builtin:WeakSet", "new WeakSet(selected)"),
        ("builtin:ObjectFromEntries", "Object.fromEntries(selected)"),
    ] {
        let source = format!(
            r#"
const choice = 'label-marker';
const log = console.log;
const source = {{
    [Symbol.iterator]() {{
        log('iterator-callback');
        return {{ next() {{ return {{ done: true }}; }} }};
    }}
}};
const selected = choice ? source : source;
console.log('public-control');
{operation};
"#
        );
        for config in constructor_configurations() {
            let input_register = config.max_registers - 1;
            let module = labelled_constructor_module(&source, input_register);
            assert!(module.instructions.iter().any(|instruction| matches!(
                instruction,
                Ir3Instruction::HostCall { capability: actual, .. } if actual.0 == capability
            )));
            for label in [Label::Public, Label::Secret] {
                let mut core = InterpreterCore::new(config.clone(), "classified-iterable-input");
                core.seed_register(input_register, Value::Bool(true)).unwrap();
                core.set_register_label(input_register, label.clone()).unwrap();
                let outcome = core.execute(&module);
                if label == Label::Public {
                    outcome.expect("public iterator selection permits its callback");
                    assert_eq!(core.console_output().len(), 2, "{capability}");
                    assert_eq!(core.console_output()[1].message, "iterator-callback");
                } else {
                    assert!(
                        matches!(outcome, Err(InterpreterError::CapabilityDenied { .. })),
                        "{capability}: {outcome:?}"
                    );
                    assert_eq!(core.console_output().len(), 1, "{capability}");
                }
                // Reaching this public sink proves the conditional PC ended;
                // only the selected iterable's register carries the input label.
                assert_eq!(core.console_output()[0].message, "public-control");
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "{capability}"
                );
            }
        }
    }
}

/// A spread element owns its whole operand (`...AssignmentExpression`):
/// `[...a ?? [], 2]`, `[...b || []]`, `[...c ? x : y]` and `[...d = [5]]`
/// spread the operand's value. The operator splits ran first, so the
/// element became a `??`, `||`, `?:` or `=` whose operand was the spread,
/// and the array held the operand's value itself (zod's
/// `[...def.checks ?? [], ...chks]` built a nested array and failed).
#[test]
fn a_spread_operand_can_contain_operators() {
    check(
        "var a; var b = [1]; var c = true; var d; \
         JSON.stringify([[...a ?? [], 2], [...b || [], 2], [0, ...b ?? [], 2], \
         [...c ? [1, 2] : [], 3], [...b && [7, 8]], [...d = [5]], d]);",
        "[[2],[1,2],[0,1,2],[1,2,3],[7,8],[5],[5]]",
    );
}

/// The same for a spread argument: `f(...c > 0 ? [a, b] : [b, a])` spreads
/// the conditional's array. bun emits this shape without parentheses
/// (date-fns' formatDistance), and it passed one argument, so date-fns
/// printed "almost NaN years".
#[test]
fn a_spread_argument_can_contain_operators() {
    check(
        "var c = 5; var a; function n() { return arguments.length; } \
         [n(...c > 0 ? [1, 2, 3] : []), Math.max(...c > 0 ? [7, 9] : [1]), n(...a ?? [1, 2]), \
         n(0, ...a || [4, 5], 6), [].concat(...c ? [[1], [2]] : []).length].join();",
        "3,9,2,4,2",
    );
}

/// Iterator, generator and async generator values report their intrinsic
/// prototypes (ES2020 22.1.5.2, 25.1.2, 25.4.1; ES2018 25.5.1):
/// %ArrayIteratorPrototype% (`next`, "Array Iterator") inherits from
/// %IteratorPrototype%, whose own @@iterator returns its receiver;
/// %GeneratorPrototype% and %AsyncGeneratorPrototype% are their function
/// kinds' `prototype` and have them as `constructor`. Object.getPrototypeOf
/// of an iterator threw ("object with property storage"), so core-js and
/// regenerator-runtime, which run `getProto(getProto([].keys()))` at load,
/// failed (xregexp's bundle did).
///
/// No-claim: Map, Set and String iterators also report
/// %ArrayIteratorPrototype% (they are array iterators over a snapshot here),
/// and a generator object reports %GeneratorPrototype% rather than its
/// function's `prototype`.
#[test]
fn iteration_intrinsic_prototypes() {
    check(
        "const getProto = Object.getPrototypeOf; const o = {}; \
         const AIP = getProto([].keys()); const IP = getProto(AIP); \
         function* g() { yield 1; } async function* ag() {} \
         const GP = getProto(g).prototype; const AGP = getProto(ag).prototype; \
         const NativeIteratorPrototype = getProto(getProto([][Symbol.iterator]())); \
         [IP === NativeIteratorPrototype, getProto(IP) === Object.prototype, \
         Object.prototype.hasOwnProperty.call(IP, Symbol.iterator), IP[Symbol.iterator].call(o) === o, \
         typeof AIP.next, AIP[Symbol.toStringTag], Object.prototype.toString.call([].values()), \
         AIP.next.call([7].values()).value, Object.isExtensible([].keys()), \
         getProto(new Map().keys()) !== Object.prototype, getProto(GP) === IP, GP[Symbol.toStringTag], \
         GP.constructor === getProto(g), typeof GP.next, GP.next.call(g()).value, \
         GP.hasOwnProperty('return'), AGP[Symbol.toStringTag], AGP.constructor === getProto(ag), \
         typeof AGP[Symbol.asyncIterator], [].keys()[Symbol.toStringTag], String([].entries())].join(' ')",
        "true true true true function Array Iterator [object Array Iterator] 7 true true true Generator \
         true function 1 true AsyncGenerator true function Array Iterator [object Array Iterator]",
    );
}

/// bd-2b8f5: array spread (`[...g()]` and generator expressions `[...gen()]`),
/// `Array.from(g())`, call-argument spread `f(...g())`, spread of an already
/// exhausted generator yielding `[]`, and mid-spread throw propagation must
/// match Node (`1,2,3|x,y|1,2,3|6|0|mid-spread` on Node v26.3.0).
#[test]
fn generator_expression_array_from_call_spread_throw_and_exhausted_bd_2b8f5() {
    check(
        "function* g() { yield 1; yield 2; yield 3; } \
         const gen = function*() { yield 'x'; yield 'y'; }; \
         function sum(a, b, c) { return a + b + c; } \
         const done = g(); for (const _ of done) {} \
         let err = ''; \
         try { [...(function*() { yield 1; throw new Error('mid-spread'); })()]; } \
         catch (e) { err = e.message; } \
         [[...g()].join(','), [...gen()].join(','), Array.from(g()).join(','), \
          sum(...g()), [...done].length, err].join('|');",
        "1,2,3|x,y|1,2,3|6|0|mid-spread",
    );
}
