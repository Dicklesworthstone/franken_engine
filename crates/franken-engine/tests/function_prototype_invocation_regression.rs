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

#[test]
fn well_known_symbols_have_stable_distinct_typed_identities() {
    let names = [
        "iterator",
        "toPrimitive",
        "hasInstance",
        "toStringTag",
        "species",
        "isConcatSpreadable",
        "unscopables",
        "asyncIterator",
        "match",
        "matchAll",
        "replace",
        "search",
        "split",
    ];
    for name in names {
        assert_eval(
            &format!("typeof Symbol.{name} + ':' + (Symbol.{name} === Symbol['{name}']);"),
            "symbol:true",
        );
    }
    let symbols = names.map(|name| format!("Symbol.{name}")).join(",");
    assert_eval(
        &format!(
            "const symbols = [{symbols}]; let unique = true; for (let i = 0; i < symbols.length; i++) {{ for (let j = i + 1; j < symbols.length; j++) {{ if (symbols[i] === symbols[j]) unique = false; }} }} unique;"
        ),
        "true",
    );
}

#[test]
fn well_known_symbol_resolution_respects_lexical_shadowing() {
    assert_eval(
        "let Symbol = {toPrimitive: 7}; Symbol.toPrimitive + ':' + Symbol['toPrimitive'];",
        "7:7",
    );
    assert_eval(
        "function f(Symbol) { return Symbol.toPrimitive; } f({toPrimitive: 11});",
        "11",
    );
}

#[test]
fn apply_length_uses_symbol_to_primitive_number_hint() {
    assert_eval(
        "let trace = ''; const length = { [Symbol.toPrimitive](hint) { trace += hint; return 2; }, valueOf() { throw 99; } }; function f(a, b) { return a + b; } const result = f.apply(null, {length, 0: 3, 1: 4}); trace + ':' + result;",
        "number:7",
    );
}

#[test]
fn computed_property_uses_symbol_to_primitive_string_hint() {
    assert_eval(
        "let trace = ''; const key = { [Symbol.toPrimitive](hint) { trace += hint; return 'x'; }, toString() { throw 99; } }; const result = { [key]: 7 }; trace + ':' + result.x;",
        "string:7",
    );
}

#[test]
fn symbol_to_primitive_can_return_a_symbol_property_key() {
    assert_eval(
        "const key = { [Symbol.toPrimitive](hint) { return Symbol.toStringTag; } }; const result = {[key]: 7, '@@toStringTag': 9}; result[Symbol.toStringTag] + ':' + result['@@toStringTag'];",
        "7:9",
    );
}

#[test]
fn throwing_symbol_to_primitive_stops_index_reads() {
    assert_eval(
        "let trace = ''; const length = { [Symbol.toPrimitive](hint) { trace += hint; throw 7; } }; const args = {length, get 0() { trace += 'bad'; return 1; }}; function f() { trace += 'bad'; } try { f.apply(null, args); } catch (e) { trace += ':' + e; } trace;",
        "number:7",
    );
}

#[test]
fn symbol_to_primitive_object_result_is_type_error() {
    assert_eval(
        "const length = { [Symbol.toPrimitive]() { return {}; } }; let result = ''; function f() {} try { f.apply(null, {length}); } catch (e) { result = e.name; } result;",
        "TypeError",
    );
}

#[test]
fn symbol_to_primitive_noncallable_hook_is_type_error() {
    assert_eval(
        "const length = { [Symbol.toPrimitive]: 3 }; let result = ''; function f() {} try { f.apply(null, {length}); } catch (e) { result = e.name; } result;",
        "TypeError",
    );
}

#[test]
fn computed_literal_key_conversion_precedes_value_and_later_keys() {
    assert_eval(
        "let trace = ''; const key = { [Symbol.toPrimitive](hint) { trace += 'k' + hint; return 'x'; } }; const result = {[key]: (trace += 'v', 7), [(trace += 'n', 'y')]: 8}; trace + ':' + result.x + ':' + result.y;",
        "kstringvn:7:8",
    );
}

#[test]
fn computed_literal_key_is_snapshotted_before_value_mutates_hook() {
    assert_eval(
        "const key = { [Symbol.toPrimitive]() { return 'before'; } }; const result = {[key]: (key[Symbol.toPrimitive] = () => 'after', 7)}; result.before + ':' + result.after;",
        "7:undefined",
    );
}

#[test]
fn computed_literal_key_ordinary_conversion_observes_string_hint_order() {
    assert_eval(
        "let trace = ''; const key = {toString() {trace += 's'; return {};}, valueOf() {trace += 'v'; return 3;}}; const result = {[key]: (trace += 'r', 9)}; trace + ':' + result[3];",
        "svr:9",
    );
}

#[test]
fn computed_literal_key_uses_inherited_hook_with_original_receiver() {
    assert_eval(
        "let trace = ''; const proto = {get [Symbol.toPrimitive]() {trace += 'g'; return function(hint) {trace += hint; return this.name;};}}; const key = Object.create(proto); key.name = 'x'; const result = {[key]: 7}; trace + ':' + result.x;",
        "gstring:7",
    );
}

#[test]
fn computed_literal_key_conversion_throw_skips_value_and_runs_finally_once() {
    assert_eval(
        "let trace = ''; const token = {}; const key = {[Symbol.toPrimitive]() {trace += 'k'; throw token;}}; try {const result = {[key]: (trace += 'bad', 7)};} catch (e) {trace += e === token ? 'c' : 'bad';} finally {trace += 'f';} trace;",
        "kcf",
    );
}

#[test]
fn computed_literal_key_getter_throw_skips_value() {
    assert_eval(
        "let trace = ''; const key = {get [Symbol.toPrimitive]() {trace += 'g'; throw 7;}}; try {const result = {[key]: (trace += 'bad', 1)};} catch(e) {trace += e;} trace;",
        "g7",
    );
}

#[test]
fn computed_literal_key_rejects_noncallable_and_nonprimitive_hooks() {
    for hook in ["3", "function() { return {}; }"] {
        assert_eval(
            &format!(
                "let trace = ''; const key = {{[Symbol.toPrimitive]: {hook}}}; try {{const result = {{[key]: (trace += 'bad', 7)}};}} catch(e) {{trace += e.name;}} trace;"
            ),
            "TypeError",
        );
    }
}

#[test]
fn computed_literal_key_nullish_exotic_hook_uses_ordinary_conversion() {
    for hook in ["null", "undefined"] {
        assert_eval(
            &format!(
                "let trace = ''; const key = {{[Symbol.toPrimitive]: {hook}, toString() {{trace += 's'; return 'x';}}, valueOf() {{throw 99;}}}}; const result = {{[key]: 7}}; trace + ':' + result.x;"
            ),
            "s:7",
        );
    }
}

#[test]
fn computed_literal_keys_preserve_primitive_property_names() {
    assert_eval(
        "const result = {[null]: 1, [undefined]: 2, [true]: 3, [7n]: 4, [-0]: 5, [1.5]: 6}; result.null + ':' + result.undefined + ':' + result.true + ':' + result[7] + ':' + result[0] + ':' + result['1.5'];",
        "1:2:3:4:5:6",
    );
}

#[test]
fn computed_literal_key_symbol_does_not_alias_its_description() {
    assert_eval(
        "const sym = Symbol('x'); const key = {[Symbol.toPrimitive]() {return sym;}}; const result = {[key]: 7, x: 9}; result[sym] + ':' + result.x + ':' + Object.getOwnPropertySymbols(result).length;",
        "7:9:1",
    );
}

#[test]
fn computed_literal_key_conversion_works_in_incremental_spread_path() {
    assert_eval(
        "let trace = ''; const key = {[Symbol.toPrimitive](hint) {trace += hint; return 'x';}}; const result = {...{a: 3}, [key]: (trace += 'v', 7), ...{b: 5}}; trace + ':' + result.a + ':' + result.x + ':' + result.b;",
        "stringv:3:7:5",
    );
}

#[test]
fn computed_literal_method_key_converts_once_and_preserves_receiver() {
    assert_eval(
        "let trace = ''; const key = {[Symbol.toPrimitive](hint) {trace += hint; return 'm';}}; const result = {x: 7, [key]() {return this.x;}}; result.m() + ':' + trace;",
        "7:string",
    );
}

#[test]
fn computed_literal_accessors_share_converted_key_and_receiver() {
    assert_eval(
        "let trace = ''; const key = {[Symbol.toPrimitive](hint) {trace += hint + ':'; return 'x';}}; const result = {backing: 3, get [key]() {return this.backing;}, set [key](v) {this.backing = v;}}; result.x = 9; result.x + ':' + trace;",
        "9:string:string:",
    );
}

#[test]
fn computed_literal_method_and_accessor_keys_preserve_symbols() {
    assert_eval(
        "const sym = Symbol('m'); const tag = Symbol('a'); const key = {[Symbol.toPrimitive]() {return sym;}}; const accessor = {[Symbol.toPrimitive]() {return tag;}}; const result = {[key]() {return 7;}, get [accessor]() {return 9;}}; result[sym]() + ':' + result[tag];",
        "7:9",
    );
}

#[test]
fn computed_literal_key_conversion_works_inside_functions_and_closures() {
    assert_eval(
        "function make(name) {return () => {const key = {[Symbol.toPrimitive]() {return name;}}; return {[key]: 7};};} const f = make('x'); f().x;",
        "7",
    );
}
