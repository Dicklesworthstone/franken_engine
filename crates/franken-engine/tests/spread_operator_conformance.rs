//! Spread operator conformance tests.
//!
//! Bead: bd-6a61n.1.12 [RC-1.12]
//!
//! Validates:
//! - Parser recognizes ...expr in array literals, object literals, and calls
//! - IR lowering handles SpreadElement expressions
//! - AST canonical values include spread metadata

#![allow(clippy::needless_borrows_for_generic_args)]

use frankenengine_engine::ast::Expression;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_ok(source: &str) -> frankenengine_engine::ast::SyntaxTree {
    parse_script(source).unwrap_or_else(|e| panic!("should parse: {source}\nerror: {e:?}"))
}

fn lower_source(source: &str) {
    let tree = parse_script(source).expect("should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "spread_conformance.js");
    lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("trace-spread", "decision-spread", "policy-spread"),
    )
    .expect("should lower");
}

// ---------------------------------------------------------------------------
// 1. Parser: spread in array literals
// ---------------------------------------------------------------------------

#[test]
fn parser_spread_in_array_literal() {
    let tree = parse_ok("[1, ...arr, 3]");
    assert!(!tree.body.is_empty());
}

#[test]
fn parser_spread_only_in_array() {
    let tree = parse_ok("[...items]");
    assert!(!tree.body.is_empty());
}

#[test]
fn parser_multiple_spreads_in_array() {
    let tree = parse_ok("[...a, ...b, ...c]");
    assert!(!tree.body.is_empty());
}

// ---------------------------------------------------------------------------
// 2. Parser: spread in object literals
// ---------------------------------------------------------------------------

#[test]
fn parser_spread_in_object_literal() {
    let tree = parse_ok("({a: 1, ...obj})");
    assert!(!tree.body.is_empty());
}

#[test]
fn parser_spread_only_in_object() {
    let tree = parse_ok("({...defaults})");
    assert!(!tree.body.is_empty());
}

// ---------------------------------------------------------------------------
// 3. Parser: spread in function call arguments
// ---------------------------------------------------------------------------

#[test]
fn parser_spread_in_call_args() {
    let tree = parse_ok("foo(...args)");
    assert!(!tree.body.is_empty());
}

#[test]
fn parser_spread_mixed_in_call_args() {
    let tree = parse_ok("foo(1, ...args, 3)");
    assert!(!tree.body.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Lowering: spread expressions lower without error
// ---------------------------------------------------------------------------

#[test]
fn lowering_spread_in_array_does_not_error() {
    lower_source("var arr = [1, 2]; var result = [...arr];");
}

#[test]
fn lowering_spread_in_call_does_not_error() {
    lower_source("function foo(a, b) { return a; } foo(...[1, 2]);");
}

#[test]
fn lowering_spread_in_object_does_not_error() {
    lower_source("var obj = {a: 1}; var copy = {...obj};");
}

// ---------------------------------------------------------------------------
// 5. AST canonical value
// ---------------------------------------------------------------------------

#[test]
fn ast_spread_element_canonical_value() {
    let expr = Expression::SpreadElement(Box::new(Expression::Identifier("arr".to_string())));
    let cv = expr.canonical_value();
    // Verify the canonical value contains spread metadata via Debug format.
    let debug = format!("{cv:?}");
    assert!(
        debug.contains("spread"),
        "canonical value should contain 'spread': {debug}"
    );
}

// ---------------------------------------------------------------------------
// 6. Nested spread
// ---------------------------------------------------------------------------

#[test]
fn parser_nested_spread_in_array() {
    let tree = parse_ok("[...[...[1, 2]]]");
    assert!(!tree.body.is_empty());
}

// ---------------------------------------------------------------------------
// 7. Rest vs Spread distinction
// ---------------------------------------------------------------------------

#[test]
fn rest_in_destructuring_still_works() {
    // Rest in binding patterns should still work after spread additions
    let tree = parse_ok("var [a, ...rest] = [1, 2, 3];");
    assert!(!tree.body.is_empty());
}

#[test]
fn rest_in_function_params_still_works() {
    let tree = parse_ok("function foo(a, ...rest) { return rest; }");
    assert!(!tree.body.is_empty());
}

// Execute through the public router: parser-only acceptance cannot establish
// that a spread actually consumes its iterator or propagates its completion.
fn assert_runtime_spread(source: &str, expected: &str) {
    let result = frankenengine_engine::HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("spread execution failed: {error}\n{source}"));
    assert_eq!(result.value, expected, "source: {source}");
}

#[test]
fn runtime_spread_consumes_custom_iterator() {
    assert_runtime_spread(
        r#"let iterable = { [Symbol.iterator]() { let n = 0; return { next() { n += 1; return { value: n, done: n > 3 }; } }; } }; [...iterable].join(":");"#,
        "1:2:3",
    );
}

#[test]
fn runtime_spread_custom_iterator_in_call_arguments() {
    assert_runtime_spread(
        r#"let iterable = { [Symbol.iterator]() { let n = 0; return { next() { n += 1; return { value: n, done: n > 2 }; } }; } }; let f = (a, b, c, d) => a + b + c + d; f(10, ...iterable, 20);"#,
        "33",
    );
}

#[test]
fn runtime_spread_custom_iterator_preserves_method_receiver() {
    assert_runtime_spread(
        r#"let iterable = { [Symbol.iterator]() { let n = 0; return { next() { n += 1; return { value: n, done: n > 2 }; } }; } }; let object = { base: 10, f(a, b) { return this.base + a + b; } }; object.f(...iterable);"#,
        "13",
    );
}

#[test]
fn runtime_spread_custom_iterator_in_constructor_arguments() {
    assert_runtime_spread(
        r#"let iterable = { [Symbol.iterator]() { let n = 0; return { next() { n += 1; return { value: n, done: n > 2 }; } }; } }; function C(a, b) { this.sum = a + b; } new C(...iterable).sum;"#,
        "3",
    );
}

#[test]
fn runtime_spread_honors_array_iterator_override() {
    assert_runtime_spread(
        r#"let array = [1, 2]; array[Symbol.iterator] = function() { return [8, 9].values(); }; [...array].join(":");"#,
        "8:9",
    );
}

#[test]
fn runtime_spread_honors_typed_array_iterator_override() {
    assert_runtime_spread(
        r#"let array = new Uint8Array([1, 2]); array[Symbol.iterator] = function() { return [8, 9].values(); }; [...array].join(":");"#,
        "8:9",
    );
}

#[test]
fn runtime_spread_resolves_iterator_and_next_once() {
    assert_runtime_spread(
        r#"let trace = ""; let count = 0; let iterator = { get next() { trace += "n"; return function() { count += 1; return { done: count > 2, value: count }; }; } }; let iterable = { get [Symbol.iterator]() { trace += "i"; return function() { trace += "c"; return iterator; }; } }; let result = [...iterable]; trace + ":" + result.join(":");"#,
        "icn:1:2",
    );
}

#[test]
fn runtime_spread_cached_next_survives_replacement() {
    assert_runtime_spread(
        r#"let count = 0; let iterator = { next() { count += 1; iterator.next = function() { throw "replacement"; }; return { done: count > 2, value: count }; } }; let iterable = { [Symbol.iterator]() { return iterator; } }; [...iterable].join(":");"#,
        "1:2",
    );
}

#[test]
fn runtime_spread_observes_done_before_value() {
    assert_runtime_spread(
        r#"let trace = ""; let count = 0; let iterable = { [Symbol.iterator]() { return { next() { count += 1; trace += "n"; return { get done() { trace += "d"; return count > 1; }, get value() { trace += "v"; return 7; } }; } }; } }; let result = [...iterable]; trace + ":" + result[0];"#,
        "ndvnd:7",
    );
}

#[test]
fn runtime_spread_keeps_sparse_source_positions() {
    assert_runtime_spread(
        r#"let source = [1, , 3, ,]; let result = [...source]; result.length + ":" + result[0] + ":" + (result[1] === undefined) + ":" + result[2] + ":" + (result[3] === undefined) + ":" + (1 in result);"#,
        "4:1:true:3:true:true",
    );
}

#[test]
fn runtime_spread_appends_after_target_elisions() {
    assert_runtime_spread(
        r#"let result = [1, , ...[3, 4]]; result.length + ":" + result[0] + ":" + (result[1] === undefined) + ":" + result[2] + ":" + result[3];"#,
        "4:1:true:3:4",
    );
}

#[test]
fn runtime_spread_invokes_index_getters_with_source_receiver() {
    assert_runtime_spread(
        r#"let source = [1, 2]; Object.defineProperty(source, "0", { get() { return this[1] + 5; } }); [...source].join(":");"#,
        "7:2",
    );
}

#[test]
fn runtime_spread_reads_live_array_length_after_getter_growth() {
    assert_runtime_spread(
        r#"let source = [1]; Object.defineProperty(source, "0", { get() { source.push(2); return 7; } }); [...source].join(":");"#,
        "7:2",
    );
}

#[test]
fn runtime_spread_stops_after_getter_shrinks_source() {
    assert_runtime_spread(
        r#"let source = [1, 2, 3]; Object.defineProperty(source, "0", { get() { source.length = 1; return 7; } }); [...source].join(":");"#,
        "7",
    );
}

#[test]
fn runtime_spread_inherited_elements_fill_holes() {
    assert_runtime_spread(
        r#"let source = [1, , 3]; Object.setPrototypeOf(source, { "1": 8, [Symbol.iterator]: source.values }); [...source].join(":");"#,
        "1:8:3",
    );
}

#[test]
fn runtime_spread_rejects_non_iterables_and_invalid_protocol_members() {
    for source in [
        r#"let caught = ""; try { [...null]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; try { [...undefined]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; try { [...7]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; try { [...{0: 7, length: 1}]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; let array = [7]; array[Symbol.iterator] = undefined; try { [...array]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; let array = [7]; array[Symbol.iterator] = null; try { [...array]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; try { [...{[Symbol.iterator]: 7}]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; try { [...{[Symbol.iterator]() { return 7; }}]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; try { [...{[Symbol.iterator]() { return {next: 7}; }}]; } catch (error) { caught = error.name; } caught;"#,
        r#"let caught = ""; try { [...{[Symbol.iterator]() { return {next() { return 7; }}; }}]; } catch (error) { caught = error.name; } caught;"#,
    ] {
        assert_runtime_spread(source, "TypeError");
    }
}

#[test]
fn runtime_spread_catches_original_iterator_acquisition_throw() {
    assert_runtime_spread(
        r#"let caught = 0; let iterable = { [Symbol.iterator]() { throw 41; } }; try { [...iterable]; } catch (error) { caught = error; } caught;"#,
        "41",
    );
}

#[test]
fn runtime_spread_catches_next_throw_without_closing_iterator() {
    assert_runtime_spread(
        r#"let trace = ""; let iterable = { [Symbol.iterator]() { return { next() { trace += "n"; throw 41; }, return() { trace += "r"; return {}; } }; } }; try { [...iterable]; } catch (error) { trace += ":" + error; } trace;"#,
        "n:41",
    );
}

#[test]
fn runtime_spread_catches_done_and_value_getter_throws() {
    for source in [
        r#"let caught = 0; let iterable = { [Symbol.iterator]() { return { next() { return { get done() { throw 41; } }; } }; } }; try { [...iterable]; } catch (error) { caught = error; } caught;"#,
        r#"let caught = 0; let iterable = { [Symbol.iterator]() { return { next() { return { done: false, get value() { throw 41; } }; } }; } }; try { [...iterable]; } catch (error) { caught = error; } caught;"#,
    ] {
        assert_runtime_spread(source, "41");
    }
}

#[test]
fn runtime_spread_preserves_guest_side_effects_on_failure() {
    assert_runtime_spread(
        r#"let writes = 0; let result = [99]; let iterable = { [Symbol.iterator]() { return { next() { writes += 1; if (writes > 1) { throw 7; } return { value: 3, done: false }; } }; } }; try { result = [...iterable]; } catch (error) {} writes + ":" + result[0];"#,
        "2:99",
    );
}

#[test]
fn runtime_spread_throw_runs_finally_once() {
    assert_runtime_spread(
        r#"let trace = ""; let iterable = { [Symbol.iterator]() { throw 7; } }; try { try { [...iterable]; } finally { trace += "f"; } } catch (error) { trace += error; } trace;"#,
        "f7",
    );
}

#[test]
fn runtime_spread_string_uses_code_points() {
    assert_runtime_spread(
        r#"let result = [..."A😀B"]; result.length + ":" + result.join(":");"#,
        "3:A:😀:B",
    );
}

fn assert_lazy_array_iterator(source: &str, expected: &str) {
    let mut engine = frankenengine_engine::HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("{error}\n{source}"));
    assert_eq!(outcome.value, expected, "source: {source}");
}

#[test]
fn lazy_values_observe_mutations_after_iterator_creation() {
    assert_lazy_array_iterator(
        r#"let a = [1, 2]; let it = a.values(); a[0] = 8; let x = it.next().value; a[1] = 9; x + ':' + it.next().value;"#,
        "8:9",
    );
}

#[test]
fn lazy_values_observe_appends_before_exhaustion() {
    assert_lazy_array_iterator(
        r#"let a = [1]; let it = a.values(); let x = it.next().value; a.push(2); x + ':' + it.next().value + ':' + it.next().done;"#,
        "1:2:true",
    );
}

#[test]
fn exhausted_array_iterators_stay_done_after_appends() {
    assert_lazy_array_iterator(
        r#"let a = []; let it = a.values(); let done = it.next().done; a.push(7); done + ':' + it.next().done;"#,
        "true:true",
    );
}

#[test]
fn lazy_iterators_observe_length_truncation() {
    assert_lazy_array_iterator(
        r#"let a = [1, 2, 3]; let it = a.values(); let x = it.next().value; a.length = 1; x + ':' + it.next().done;"#,
        "1:true",
    );
}

#[test]
fn lazy_values_defer_getters_until_next() {
    assert_lazy_array_iterator(
        r#"let calls = 0, a = [1]; Object.defineProperty(a, '0', {get() { calls += 1; return 7; }}); let it = a.values(); let before = calls; let x = it.next().value; before + ':' + calls + ':' + x;"#,
        "0:1:7",
    );
}

#[test]
fn lazy_keys_never_read_indexed_getters() {
    assert_lazy_array_iterator(
        r#"let calls = 0, a = [1]; Object.defineProperty(a, '0', {get() { calls += 1; throw 7; }}); let it = a.keys(); it.next().value + ':' + it.next().done + ':' + calls;"#,
        "0:true:0",
    );
}

#[test]
fn lazy_entries_get_current_values_and_allocate_independent_pairs() {
    assert_lazy_array_iterator(
        r#"let a = [1, 2]; let it = a.entries(); let first = it.next().value; a[1] = 9; let second = it.next().value; first.join(':') + ':' + second.join(':') + ':' + (first === second);"#,
        "0:1:1:9:false",
    );
}

#[test]
fn throwing_array_getter_advances_iterator_before_next_retry() {
    assert_lazy_array_iterator(
        r#"let a = [1, 2]; Object.defineProperty(a, '0', {get() { throw 'stop'; }}); let it = a.values(); let error = ''; try { it.next(); } catch (e) { error = e; } error + ':' + it.next().value + ':' + it.next().done;"#,
        "stop:2:true",
    );
}

#[test]
fn lazy_array_iterators_get_inherited_values_for_holes() {
    assert_lazy_array_iterator(
        r#"let a = [1, , 3]; Object.setPrototypeOf(a, {1: 8}); let it = [].values.call(a); it.next().value + ':' + it.next().value + ':' + it.next().value;"#,
        "1:8:3",
    );
}

#[test]
fn lazy_generic_array_iterator_reads_length_each_time() {
    assert_lazy_array_iterator(
        r#"let reads = 0; let a = {0: 'a', 1: 'b', get length() { reads += 1; return 2; }}; let it = [].values.call(a); let before = reads; let first = it.next().value; let second = it.next().value; let done = it.next().done; before + ':' + reads + ':' + first + second + ':' + done;"#,
        "0:3:ab:true",
    );
}

#[test]
fn lazy_generic_array_iterator_truncates_fractional_lengths() {
    assert_lazy_array_iterator(
        r#"let it = [].values.call({0: 7, 1: 8, length: 1.8}); it.next().value + ':' + it.next().done;"#,
        "7:true",
    );
}

#[test]
fn lazy_generic_array_iterator_rejects_bigint_length_on_next() {
    assert_lazy_array_iterator(
        r#"let it = [].values.call({length: 1n}); let error = ''; try { it.next(); } catch (e) { error = e.name; } error;"#,
        "TypeError",
    );
}

#[test]
fn spread_consumes_lazy_iterator_from_current_position() {
    assert_lazy_array_iterator(
        r#"let a = [1, 2], it = a.values(); it.next(); a.push(3); [...it].join(':');"#,
        "2:3",
    );
}

#[test]
fn array_iterator_creation_does_not_expand_sparse_length() {
    assert_lazy_array_iterator(
        r#"let a = []; a.length = 4294967295; let it = a.keys(); it.next().value + ':' + it.next().value;"#,
        "0:1",
    );
}

#[test]
fn rest_suffix_observes_getters_without_reading_skipped_prefix() {
    assert_lazy_array_iterator(
        r#"let trace = ''; let a = [1, 2, 3]; Object.defineProperty(a, '0', {get() { trace += 'a'; return 1; }}); Object.defineProperty(a, '1', {get() { trace += 'b'; return 7; }}); let [head, ...tail] = a; trace + ':' + head + ':' + tail.join(':');"#,
        "ab:1:7:3",
    );
}

#[test]
fn throwing_rest_suffix_getter_reaches_guest_catch() {
    assert_lazy_array_iterator(
        r#"let a = [1]; Object.defineProperty(a, '0', {get() { throw 'tail'; }}); let error = ''; try { let [...tail] = a; } catch (e) { error = e; } error;"#,
        "tail",
    );
}
