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
        &LoweringContext::new(
            "util-equal-trace",
            "util-equal-decision",
            "util-equal-policy",
        ),
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

const ARRAY_BUFFERS: &str = r#"
const eq = require('util').isDeepStrictEqual;
const a = new Uint8Array([1, 2, 3]).buffer;
const b = new Uint8Array([1, 2, 3]).buffer;
const c = new Uint8Array([1, 9, 3]).buffer;
console.log(eq(a, b), eq(b, a), eq(a, c), eq(c, a));
console.log(eq(new ArrayBuffer(1), new ArrayBuffer(2)), eq(new ArrayBuffer(0), new ArrayBuffer(0)));
a.metadata = {revision: 1}; b.metadata = {revision: 2};
console.log(eq(a, b), eq(b, a));
console.log(eq(a, Object.create(ArrayBuffer.prototype)));
"#;

#[test]
fn array_buffers_compare_payload_length_bytes_and_custom_properties() {
    assert_output(
        ARRAY_BUFFERS,
        "true true false false\nfalse true\nfalse false\nfalse",
    );
}

const DATA_VIEWS: &str = r#"
const eq = require('util').isDeepStrictEqual;
const a = new Uint8Array([9, 1, 2, 8]);
const b = new Uint8Array([1, 2, 7, 6]);
const x = new DataView(a.buffer, 1, 2);
const y = new DataView(b.buffer, 0, 2);
console.log(eq(x, y), eq(y, x));
a[0] = 100; a[3] = 200;
console.log(eq(x, y));
a[2] = 3;
console.log(eq(x, y), eq(y, x));
console.log(eq(new DataView(a.buffer, 0, 1), new DataView(a.buffer, 0, 2)));
console.log(eq(new DataView(a.buffer, 0, 0), new DataView(b.buffer, 3, 0)));
"#;

#[test]
fn data_views_compare_only_the_visible_byte_range() {
    assert_output(DATA_VIEWS, "true true\ntrue\nfalse false\nfalse\ntrue");
}

const TYPED_ARRAY_VALUES: &str = r#"
const eq = require('util').isDeepStrictEqual;
console.log(eq(new Float64Array([NaN, 1]), new Float64Array([NaN, 1])));
console.log(eq(new Float64Array([-0]), new Float64Array([0])));
console.log(eq(new Uint8Array([1]), new Uint16Array([1])));
const a = new Uint8Array([9, 1, 2, 8]);
const b = new Uint8Array([1, 2]);
console.log(eq(a.subarray(1, 3), b), eq(b, a.subarray(1, 3)));
console.log(eq(new Int16Array([1, -2]), new Int16Array([1, -3])));
"#;

#[test]
fn typed_arrays_preserve_element_brand_nan_signed_zero_and_slice_semantics() {
    assert_output(TYPED_ARRAY_VALUES, "true\nfalse\nfalse\ntrue true\nfalse");
}

const ERROR_STATE: &str = r#"
const eq = require('util').isDeepStrictEqual;
function errorWith(name, value) {
  const error = new Error('failure');
  Object.defineProperty(error, name, {value: value, writable: true, configurable: true});
  return error;
}
const a = errorWith('cause', {code: 1});
const b = errorWith('cause', {code: 1});
const c = errorWith('cause', {code: 2});
console.log(eq(a, b), eq(a, c), eq(c, a));
console.log(eq(errorWith('cause', undefined), new Error('failure')));
console.log(eq(errorWith('errors', [new Error('one')]), errorWith('errors', [new Error('two')])));
console.log(eq(errorWith('errors', [new Error('one')]), errorWith('errors', [new Error('one')])));
"#;

#[test]
fn error_causes_and_error_lists_compare_even_when_not_enumerable() {
    assert_output(ERROR_STATE, "true false false\nfalse\nfalse\ntrue");
}

const OPAQUE_AND_DATE_STATE: &str = r#"
const eq = require('util').isDeepStrictEqual;
const key = {};
const a = new WeakMap([[key, 1]]);
const b = new WeakMap([[key, 1]]);
console.log(eq(a, b), eq(b, a), eq(a, a));
const x = new WeakSet([key]);
const y = new WeakSet([key]);
console.log(eq(x, y), eq(y, x), eq(x, x));
console.log(eq(new Date(7), new Date(7)), eq(new Date(NaN), new Date(NaN)));
const first = /value/g; first.lastIndex = 1;
const second = /value/g; second.lastIndex = 2;
console.log(eq(first, second));
"#;

#[test]
fn weak_collections_are_identity_only_and_native_date_state_is_compared() {
    assert_output(
        OPAQUE_AND_DATE_STATE,
        "false false true\nfalse false true\ntrue false\nfalse",
    );
}

const BYTE_VIEW_HYGIENE: &str = r#"
const eq = require('util').isDeepStrictEqual;
const Uint8Array = 'guest-byte-view';
const a = new globalThis.Uint8Array([1, 2]).buffer;
const b = new globalThis.Uint8Array([1, 3]).buffer;
console.log(eq(a, b), Uint8Array);
"#;

#[test]
fn guest_byte_view_bindings_do_not_capture_the_comparison_constructor() {
    assert_output(BYTE_VIEW_HYGIENE, "false guest-byte-view");
}

// The Node 22.16.0 comparator overflows on this self-referential cause.
// This is a termination/correctness invariant, NOT a Node-parity golden.
const CYCLIC_ERROR_CAUSES: &str = r#"
const eq = require('util').isDeepStrictEqual;
const a = new Error('cycle');
const b = new Error('cycle');
Object.defineProperty(a, 'cause', {value: a});
Object.defineProperty(b, 'cause', {value: b});
console.log(eq(a, b), eq(b, a));
b.message = 'different';
console.log(eq(a, b), eq(b, a));
"#;

#[test]
fn cyclic_error_causes_terminate_without_hiding_different_messages() {
    assert_output(CYCLIC_ERROR_CAUSES, "true true\nfalse false");
}
