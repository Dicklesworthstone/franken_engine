//! First-class call/apply and observable array-like argument extraction.

use frankenengine_engine::HybridRouter;

fn assert_eval(source: &str, expected: &str) {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("{error}\n{source}"));
    assert_eq!(outcome.value, expected, "{source}");
}

#[test]
fn builtin_call_preserves_receiver_and_argument_order() {
    assert_eval(
        "let a = []; let n = [].push.call(a, 3, 5); n + ':' + a.join(':');",
        "2:3:5",
    );
}

#[test]
fn ordinary_call_preserves_explicit_this() {
    assert_eval(
        "function f(a, b) { return this.x + a + b; } f.call({x: 10}, 2, 3);",
        "15",
    );
}

#[test]
fn closure_call_retains_captured_bindings() {
    assert_eval(
        "function outer(x) { return function(y) { return x + this.z + y; }; } const f = outer(4); f.call({z: 5}, 6);",
        "15",
    );
}

#[test]
fn arrow_call_does_not_replace_lexical_this() {
    assert_eval(
        "const o = { x: 7, make() { return () => this.x; } }; const f = o.make(); f.call({x: 99});",
        "7",
    );
}

#[test]
fn strict_call_does_not_box_or_replace_primitive_this() {
    assert_eval(
        "function f() { 'use strict'; return this; } (f.call(null) === null) + ':' + (f.call(0) === 0) + ':' + (f.call(false) === false);",
        "true:true:true",
    );
}

#[test]
fn call_works_as_an_extracted_first_class_value() {
    assert_eval(
        "const call = [].push.call; let a = []; call.call([].push, a, 2, 4); a.join(':');",
        "2:4",
    );
}

#[test]
fn computed_call_member_uses_the_same_intrinsic() {
    assert_eval(
        "let a = []; const key = 'call'; [].push[key](a, 8); a[0];",
        "8",
    );
}

#[test]
fn generic_array_iterator_is_reachable_through_call() {
    assert_eval(
        "let o = {0: 3, 1: 5, length: 2}; const it = [].values.call(o); it.next().value + ':' + it.next().value + ':' + it.next().done;",
        "3:5:true",
    );
}

#[test]
fn generic_array_iterator_observes_inherited_values() {
    assert_eval(
        "let o = Object.create({0: 9}); o.length = 1; const it = [].values.call(o); it.next().value;",
        "9",
    );
}

#[test]
fn apply_to_builtin_uses_array_like_properties_not_iteration() {
    assert_eval(
        "let a = []; const args = {0: 2, 1: 3, length: 2, get [Symbol.iterator]() { throw 99; }}; [].push.apply(a, args); a.join(':');",
        "2:3",
    );
}

#[test]
fn apply_reads_length_once_before_indexed_getters() {
    assert_eval(
        "let trace = ''; let args = { get length() { trace += 'l'; return 2; }, get 0() { trace += 'a'; return 3; }, get 1() { trace += 'b'; return 4; } }; function f(a, b) { trace += 'f'; return a + b; } const result = f.apply(null, args); trace + ':' + result;",
        "labf:7",
    );
}

#[test]
fn apply_snapshots_length_but_not_later_property_values() {
    assert_eval(
        "let args = { length: 2, get 0() { args.length = 0; args[1] = 7; return 3; }, 1: 4 }; function f(a, b) { return a + ':' + b; } f.apply(null, args);",
        "3:7",
    );
}

#[test]
fn apply_reads_inherited_numeric_properties() {
    assert_eval(
        "let args = Object.create({1: 8}); args[0] = 3; args.length = 2; function f(a, b) { return a + b; } f.apply(null, args);",
        "11",
    );
}

#[test]
fn apply_missing_properties_are_undefined() {
    assert_eval(
        "function f(a, b) { return a + ':' + (b === undefined); } f.apply(null, {0: 3, length: 2});",
        "3:true",
    );
}

#[test]
fn apply_null_and_undefined_mean_no_arguments() {
    assert_eval(
        "function f(a = 7) { return a; } f.apply(null, null) + f.apply(null) + f.apply(null, undefined);",
        "21",
    );
}

#[test]
fn apply_to_length_truncates_fractional_lengths() {
    assert_eval(
        "function f(a, b, c) { return a + ':' + b + ':' + (c === undefined); } f.apply(null, {0: 3, 1: 4, 2: 5, length: 2.9});",
        "3:4:true",
    );
}

#[test]
fn apply_length_conversion_calls_value_of_before_to_string() {
    assert_eval(
        "let trace = ''; let length = { valueOf() { trace += 'v'; return 1; }, toString() { trace += 's'; return '2'; } }; function f(a) { return a; } let result = f.apply(null, {0: 8, length}); trace + ':' + result;",
        "v:8",
    );
}

#[test]
fn apply_length_conversion_falls_back_to_to_string() {
    assert_eval(
        "let trace = ''; let length = { valueOf() { trace += 'v'; return {}; }, toString() { trace += 's'; return '1'; } }; function f(a) { return a; } let result = f.apply(null, {0: 8, length}); trace + ':' + result;",
        "vs:8",
    );
}

#[test]
fn apply_nondecimal_string_length_is_numeric() {
    assert_eval(
        "function f(a, b) { return a + b; } f.apply(null, {0: 2, 1: 3, length: '0x2'});",
        "5",
    );
}

#[test]
fn apply_invalid_string_and_negative_lengths_are_zero() {
    assert_eval(
        "function f(a = 7) { return a; } f.apply(null, {length: 'not a number'}) + f.apply(null, {length: -2}) + f.apply(null, {length: 'inf'});",
        "21",
    );
}

#[test]
fn apply_indexed_throw_stops_later_reads_and_target_execution() {
    assert_eval(
        "let trace = ''; let args = { length: 3, get 0() { trace += 'a'; return 1; }, get 1() { trace += 'b'; throw 7; }, get 2() { trace += 'c'; return 3; } }; function f() { trace += 'f'; } try { f.apply(null, args); } catch (e) { trace += e; } trace;",
        "ab7",
    );
}

#[test]
fn apply_rejects_noncallable_target_before_reading_length() {
    assert_eval(
        "let trace = ''; let args = { get length() { trace += 'l'; return 0; } }; const apply = [].push.apply; try { apply.call(3, null, args); } catch (e) { trace += e.name; } trace;",
        "TypeError",
    );
}

#[test]
fn apply_rejects_primitive_argument_list() {
    assert_eval(
        "function f() { return 0; } let result = ''; try { f.apply(null, '12'); } catch (e) { result = e.name; } result;",
        "TypeError",
    );
}

#[test]
fn apply_rejects_bigint_length() {
    assert_eval(
        "function f() { return 0; } let result = ''; try { f.apply(null, {length: 1n}); } catch (e) { result = e.name; } result;",
        "TypeError",
    );
}

#[test]
fn apply_proxies_observe_get_order_and_original_receiver() {
    assert_eval(
        "let trace = ''; let p = new Proxy({0: 4, 1: 5, length: 2}, { get(t, k, r) { trace += k + ':'; return t[k]; } }); function f(a, b) { return a + b; } const result = f.apply(null, p); trace + result;",
        "length:0:1:9",
    );
}

#[test]
fn forwarding_call_preserves_thrown_value_identity() {
    assert_eval(
        "const token = {}; function f() { throw token; } let same = false; try { f.call(null); } catch (e) { same = e === token; } same;",
        "true",
    );
}
