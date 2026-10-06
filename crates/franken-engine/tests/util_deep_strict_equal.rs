//! Structural equality through the real util-module parse/lower/execute path.
//! Collection keys and values are unordered, but matches must be one-to-one;
//! cycle state must never leak out of a failed candidate comparison.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn assert_output(source: &str, expected: &str) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "util-deep-strict-equal.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("regression source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "util-deep-strict-equal.js"),
        &LoweringContext::new("util-equal-trace", "util-equal-decision", "util-equal-policy"),
    )
    .expect("util comparison lowers without filesystem authority")
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "util-deep-strict-equal");
    let result = core.execute(&module).expect("util comparison executes");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "comparison must retain exact heap accounting"
    );
    let actual = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(actual, expected);
}

const UNORDERED: &str = r#"
const eq = require('util').isDeepStrictEqual;
const a = new Map([[{id: 1}, {value: [2]}], [{id: 3}, new Set([{x: 4}, {x: 5}])]]);
const b = new Map([[{id: 3}, new Set([{x: 5}, {x: 4}])], [{id: 1}, {value: [2]}]]);
console.log(eq(a, b), eq(b, a));
console.log(eq(new Set([{x: [1]}, {y: 2}]), new Set([{y: 2}, {x: [1]}])));
console.log(eq(new Map([[{id: 1}, 2]]), new Map([[{id: 1}, 3]])));
console.log(eq(new Set([NaN, 0]), new Set([-0, NaN])), eq(new Set([1]), new Set(['1'])));
"#;

#[test]
fn nested_collection_objects_compare_structurally_in_either_order() {
    assert_output(UNORDERED, "true true\ntrue\nfalse\ntrue false");
}

const ONE_TO_ONE: &str = r#"
const eq = require('node:util').isDeepStrictEqual;
const a = new Map([[{key: 1}, 'a'], [{key: 1}, 'b']]);
const b = new Map([[{key: 1}, 'b'], [{key: 1}, 'a']]);
const c = new Map([[{key: 1}, 'a'], [{key: 1}, 'a']]);
console.log(eq(a, b), eq(b, a), eq(c, b), eq(b, c));
const x = new Set([{value: 1}, {value: 1}]);
const y = new Set([{value: 1}, {value: 2}]);
console.log(eq(x, y), eq(y, x), eq(x, new Set([{value: 1}, {value: 1}])));
"#;

#[test]
fn unordered_matching_never_reuses_a_right_hand_entry() {
    assert_output(ONE_TO_ONE, "true true false false\nfalse false true");
}

const CYCLES: &str = r#"
const eq = require('util').isDeepStrictEqual;
const a = new Map(); a.set(a, {value: 1});
const b = new Map(); b.set(b, {value: 1});
const c = new Map(); c.set(c, {value: 2});
console.log(eq(a, b), eq(b, a), eq(a, c), eq(c, a));
const x = new Set(); x.add(x); x.add({value: 1});
const y = new Set(); y.add({value: 1}); y.add(y);
console.log(eq(x, y), eq(y, x));
const left = {}; left.self = left;
const right = {}; right.self = right;
console.log(eq(left, right));
const shared = {value: 7};
console.log(eq({a: shared, b: shared}, {a: {value: 7}, b: {value: 7}}));
"#;

#[test]
fn cyclic_maps_sets_and_shared_acyclic_values_terminate_correctly() {
    assert_output(CYCLES, "true true false false\ntrue true\ntrue\ntrue");
}

const CANDIDATE_ROLLBACK: &str = r#"
const eq = require('util').isDeepStrictEqual;
const leftShared = {value: 1};
const rightShared = {value: 2};
const a = new Set([{child: leftShared, order: 1}, {child: leftShared, order: 2}]);
const b = new Set([{child: rightShared, order: 2}, {child: rightShared, order: 1}]);
console.log(eq(a, b), eq(b, a));
const c = new Set([{child: {value: 1}, order: 2}, {child: {value: 1}, order: 1}]);
console.log(eq(a, c), eq(c, a));
const m = new Map([[{child: leftShared}, 1], [{child: leftShared}, 2]]);
const n = new Map([[{child: rightShared}, 2], [{child: rightShared}, 1]]);
console.log(eq(m, n), eq(n, m));
"#;

#[test]
fn failed_candidates_do_not_poison_cycle_memoization() {
    assert_output(CANDIDATE_ROLLBACK, "false false\ntrue true\nfalse false");
}

const ENUMERABLE_KEYS: &str = r#"
const eq = require('util').isDeepStrictEqual;
const symbol = Symbol('value');
const a = {}; a[symbol] = {value: 1};
const b = {}; b[symbol] = {value: 1};
const c = {}; c[symbol] = {value: 2};
const d = {}; d[Symbol('value')] = {value: 1};
console.log(eq(a, b), eq(a, c), eq(a, d));
const hidden = {};
Object.defineProperty(hidden, symbol, {value: 42});
console.log(eq(hidden, {}), eq(a, hidden));
const sparse = new Array(1);
console.log(eq(sparse, [undefined]), eq(sparse, new Array(1)));
console.log(eq({x: undefined}, {y: undefined}), eq({a: 1, b: 2}, {b: 2, a: 1}));
"#;

#[test]
fn enumerable_symbol_keys_and_sparse_array_holes_are_significant() {
    assert_output(
        ENUMERABLE_KEYS,
        "true false false\ntrue false\nfalse true\nfalse true",
    );
}

const COLLECTION_PROPERTIES: &str = r#"
const eq = require('util').isDeepStrictEqual;
const a = new Map([[{id: 1}, {value: 2}]]);
const b = new Map([[{id: 1}, {value: 2}]]);
a.metadata = {revision: 1}; b.metadata = {revision: 1};
console.log(eq(a, b), eq(b, a));
b.metadata.revision = 2;
console.log(eq(a, b), eq(b, a));
const symbol = Symbol('metadata');
const x = new Set([{value: 1}]);
const y = new Set([{value: 1}]);
x[symbol] = 1; y[symbol] = 2;
console.log(eq(x, y), eq(y, x));
"#;

#[test]
fn collection_contents_do_not_hide_custom_enumerable_properties() {
    assert_output(COLLECTION_PROPERTIES, "true true\nfalse false\nfalse false");
}

const GLOBAL_HYGIENE: &str = r#"
const {isDeepStrictEqual: eq} = require('util');
const Map = 'guest-map';
const Set = 'guest-set';
const a = new globalThis.Map([[{id: 1}, new globalThis.Set([{value: 2}])]]);
const b = new globalThis.Map([[{id: 1}, new globalThis.Set([{value: 2}])]]);
console.log(eq(a, b), Map, Set);
"#;

#[test]
fn guest_map_and_set_bindings_do_not_capture_module_intrinsics() {
    assert_output(GLOBAL_HYGIENE, "true guest-map guest-set");
}
