//! Native Map/Set key identity, constructor accounting and iteration regressions.
//! Exercises the real parser, lowerer and both native execution profiles.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn assert_source(source: &str, expected: &str) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "collection-keys.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("collection key source must parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "collection-keys.js"),
        &LoweringContext::new("keys-trace", "keys-decision", "keys-policy"),
    )
    .expect("collection key source must lower")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "collection-keys");
        let result = core.execute(&module).expect("collection keys must execute");
        assert_eq!(result.value, Value::str(expected), "{source}");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "constructor or key accounting drift: {source}"
        );
    }
}

macro_rules! source_case {
    ($name:ident, $source:literal, $expected:literal) => {
        #[test]
        fn $name() {
            assert_source($source, $expected);
        }
    };
}

source_case!(
    bigint_constructor_and_method_keys_share_one_identity,
    r#"
const map = new Map([[1n, 'one'], [2n, 'two'], [1, 'number'], ['1', 'string']]);
map.set(1n, 'updated');
[map.size, map.get(1n), map.get(2n), map.get(1), map.get('1')].join('|');
"#,
    "4|updated|two|number|string"
);

source_case!(
    bigint_delete_does_not_delete_another_key,
    r#"
const map = new Map();
map.set(123456789012345678901234567890n, 'large');
map.set(-123456789012345678901234567890n, 'negative');
const removed = map.delete(123456789012345678901234567890n);
[removed, map.size, map.has(-123456789012345678901234567890n),
 map.get(-123456789012345678901234567890n)].join('|');
"#,
    "true|1|true|negative"
);

source_case!(
    symbols_with_equal_descriptions_are_distinct,
    r#"
const a = Symbol('key'); const b = Symbol('key');
const map = new Map([[a, 'a'], [b, 'b']]);
const set = new Set([a, b, a]);
[map.size, map.get(a), map.get(b), set.size, set.delete(a), set.has(b),
 map.delete(a), map.has(b)].join('|');
"#,
    "2|a|b|2|true|true|true|true"
);

source_case!(
    map_iteration_recovers_symbol_identity,
    r#"
const a = Symbol('a'); const b = Symbol('b');
const map = new Map([[a, 10], [b, 20]]);
const keys = Array.from(map.keys());
const entries = Array.from(map);
[keys[0] === a, keys[1] === b, entries[0][0] === a,
 entries[1][0] === b, entries[1][1]].join('|');
"#,
    "true|true|true|true|20"
);

source_case!(
    closures_remain_distinct_and_iterated_keys_are_callable,
    r#"
function make(n) { return () => n; }
const f = make(11); const g = make(22);
const map = new Map([[f, 'f'], [g, 'g']]);
const keys = Array.from(map.keys());
[map.size, map.get(f), map.get(g), keys[0] === f, keys[1] === g,
 keys[0](), keys[1]()].join('|');
"#,
    "2|f|g|true|true|11|22"
);

source_case!(
    builtin_functions_do_not_alias_user_functions,
    r#"
const f = () => 7;
const map = new Map([[f, 'user'], [Object, 'object'], [Array, 'array']]);
const keys = Array.from(map.keys());
[map.size, map.get(f), map.get(Object), map.get(Array),
 keys[1] === Object, keys[2] === Array].join('|');
"#,
    "3|user|object|array|true|true"
);

source_case!(
    promises_retain_handle_identity,
    r#"
const p = Promise.resolve(1); const q = Promise.resolve(1);
const map = new Map([[p, 'p'], [q, 'q']]);
const keys = Array.from(map.keys());
const set = new Set([p, q, p]);
[map.size, map.get(p), map.get(q), set.size, keys[0] === p,
 keys[1] === q, set.delete(p), set.has(q)].join('|');
"#,
    "2|p|q|2|true|true|true|true"
);

source_case!(
    generator_instances_are_distinct_keys,
    r#"
function* values() { yield 9; }
const a = values(); const b = values();
const map = new Map([[a, 'a'], [b, 'b']]);
const keys = Array.from(map.keys());
[map.size, map.get(a), map.get(b), keys[0] === a, keys[1] === b,
 keys[0].next().value].join('|');
"#,
    "2|a|b|true|true|9"
);

source_case!(
    bigint_iteration_recovers_exact_digits_and_sign,
    r#"
const a = 123456789012345678901234567890n;
const b = -123456789012345678901234567890n;
const map = new Map([[a, 1], [b, 2]]);
const keys = Array.from(map.keys());
[keys[0] === a, keys[1] === b, typeof keys[0], typeof keys[1]].join('|');
"#,
    "true|true|bigint|bigint"
);

source_case!(
    lone_surrogates_do_not_collide_with_each_other_or_replacement,
    r#"
const map = new Map([['\uD800', 'high'], ['\uD801', 'other'],
 ['\uDC00', 'low'], ['\uFFFD', 'replacement'], ['x:D800', 'literal']]);
const keys = Array.from(map.keys());
[map.size, map.get('\uD800'), map.get('\uD801'), map.get('\uDC00'),
 map.get('\uFFFD'), map.get('x:D800'), keys[0].charCodeAt(0),
 keys[1].charCodeAt(0), keys[2].charCodeAt(0)].join('|');
"#,
    "5|high|other|low|replacement|literal|55296|55297|56320"
);

source_case!(
    set_uses_exact_utf16_identity,
    r#"
const set = new Set(['\uD800', '\uD801', '\uFFFD', '\uD800']);
[set.size, set.delete('\uD800'), set.has('\uD801'),
 set.has('\uFFFD'), set.has('\uD800')].join('|');
"#,
    "3|true|true|true|false"
);

source_case!(
    map_zero_keys_use_same_value_zero,
    r#"
const map = new Map([[-0, 'first'], [0, 'second']]);
map.set(-0, 'third');
const key = Array.from(map.keys())[0];
[map.size, map.get(0), map.get(-0), 1 / key,
 map.delete(-0), map.has(0)].join('|');
"#,
    "1|third|third|Infinity|true|false"
);

source_case!(
    set_zero_is_canonicalized_at_construction_and_add,
    r#"
const a = new Set([-0]); const b = new Set(); b.add(-0); b.add(0);
const x = Array.from(a)[0]; const y = Array.from(b)[0];
[a.size, b.size, a.has(0), b.has(-0), 1 / x, 1 / y].join('|');
"#,
    "1|1|true|true|Infinity|Infinity"
);

source_case!(
    nan_keys_overwrite_without_colliding_with_strings,
    r#"
const map = new Map([[NaN, 1], [0 / 0, 2], ['NaN', 3]]);
const set = new Set([NaN, 0 / 0, 'NaN']);
[map.size, map.get(NaN), map.get('NaN'), set.size,
 set.has(NaN), map.delete(0 / 0), map.has(NaN)].join('|');
"#,
    "2|2|3|2|true|true|false"
);

source_case!(
    number_representations_and_infinities_have_consistent_keys,
    r#"
const map = new Map([[1, 'one'], [Infinity, 'positive'], [-Infinity, 'negative'],
 [1e21, 'large'], [1e-7, 'small']]);
map.set(2 / 2, 'same');
const keys = Array.from(map.keys());
[map.size, map.get(1.0), map.get(Infinity), map.get(-Infinity),
 map.get(1000000000000000000000), map.get(0.0000001), keys[3] === 1e21].join('|');
"#,
    "5|same|positive|negative|large|small|true"
);

source_case!(
    key_type_domains_are_disjoint,
    r#"
const symbol = Symbol('0'); const object = {};
const set = new Set([0, 0n, '0', false, null, undefined, symbol, object]);
[set.size, set.has(0n), set.has(symbol), set.has(object),
 set.delete(false), set.has(0), set.has('0')].join('|');
"#,
    "8|true|true|true|true|true|true"
);

source_case!(
    keys_never_invoke_guest_conversion,
    r#"
let calls = 0;
const key = { toString() { calls++; throw 'toString'; },
 valueOf() { calls++; throw 'valueOf'; }, toJSON() { calls++; throw 'toJSON'; } };
key[Symbol.toPrimitive] = () => { calls++; throw 'primitive'; };
const map = new Map([[key, 7]]); const set = new Set([key]);
[map.get(key), map.has(key), set.has(key), calls,
 Array.from(map.keys())[0] === key].join('|');
"#,
    "7|true|true|0|true"
);

source_case!(
    updating_does_not_move_a_key_but_reinsertion_does,
    r#"
const a = Symbol('a'); const b = Symbol('b'); const c = 3n;
const map = new Map([[a, 1], [b, 2], [c, 3]]);
map.set(a, 10); map.delete(b); map.set(b, 20);
const keys = Array.from(map.keys());
[map.size, keys[0] === a, keys[1] === c, keys[2] === b,
 map.get(a), map.get(b)].join('|');
"#,
    "3|true|true|true|10|20"
);

source_case!(
    foreach_receives_original_keys_and_collection,
    r#"
const symbol = Symbol('x'); const fn = () => 1;
const map = new Map([[symbol, 's'], [fn, 'f'], [7n, 'b']]);
let text = '';
map.forEach((value, key, owner) => {
 text += value + ':' + (owner === map) + ':' + (map.get(key) === value) + '|';
});
text;
"#,
    "s:true:true|f:true:true|b:true:true|"
);

source_case!(
    duplicate_constructor_entries_account_for_replacement_growth,
    r#"
const a = Symbol('same');
const map = new Map([[a, 'x'], [a, 'a substantially larger replacement value']]);
const set = new Set([a, a, a]);
[map.size, map.get(a), set.size].join('|');
"#,
    "1|a substantially larger replacement value|1"
);
