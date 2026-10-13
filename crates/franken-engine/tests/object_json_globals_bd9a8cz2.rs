//! Source-to-runtime regression coverage for standard Object, JSON, Array,
//! String, Number, and Reflect members (bd-9a8cz.2, bd-9vouw.366).
//!
//! These globals own ordinary mutable properties. Calls and reads resolve
//! their live values, preserve the receiver and evaluate the member before
//! arguments. Saved native references retain their original behavior.
//!
//! Also covers bd-ck8ui's Array RHS for instanceof: an unshadowed global
//! constructor and a shadowed user constructor keep normal prototype semantics.

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    format!("{outcome:?}")
        .split("value: \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn object_keys_returns_own_property_names() {
    assert_eq!(
        eval_value("let o = {x: 1, y: 2, z: 3}; Object.keys(o).length;"),
        "3"
    );
    assert_eq!(eval_value("let o = {}; Object.keys(o).length;"), "0");
}

#[test]
fn object_keys_length_is_primitive() {
    // A source method read stays mutable; this public-only program must
    // still execute the native result's primitive length conversion.
    assert_eq!(
        eval_value("Object.keys({a: 1, b: 2}).length.toString();"),
        "2"
    );
}

#[test]
fn object_keys_finite_array_methods_stay_closed() {
    // Mutable source method reads retain the program's label bound, allowing
    // this public-only sequence of native array operations to execute.
    assert_eq!(
        eval_value("Object.keys({b: 1, a: 2}).sort().join(',');"),
        "a,b"
    );
}

#[test]
fn object_values_and_entries() {
    assert_eq!(eval_value("let o = {x: 10}; Object.values(o)[0];"), "10");
    assert_eq!(eval_value("let o = {x: 5}; Object.entries(o).length;"), "1");
}

#[test]
fn json_stringify_primitive() {
    // A primitive stringifies without embedded quotes (keeps the eval-value
    // extraction simple).
    assert_eq!(eval_value("JSON.stringify(5);"), "5");
}

#[test]
fn json_round_trips_a_primitive() {
    // Both calls resolve their current members and round-trip primitives.
    assert_eq!(eval_value("JSON.parse(JSON.stringify(42));"), "42");
    assert_eq!(eval_value("JSON.parse(JSON.stringify(true));"), "true");
}

#[test]
fn bare_array_rhs_supports_instanceof_arrays() {
    assert_eq!(eval_value("[] instanceof Array;"), "true");
}

#[test]
fn bare_array_rhs_rejects_non_arrays_for_instanceof() {
    assert_eq!(eval_value("let o = {}; o instanceof Array;"), "false");
}

#[test]
fn shadowed_array_rhs_keeps_user_constructor_instanceof() {
    assert_eq!(
        eval_value("let Array = function () {}; [] instanceof Array;"),
        "false"
    );
}

fn check_console(source: &str, expected: &[&str]) {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed for {source:?}: {error}"));
    let actual: Vec<_> = outcome
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn replaced_static_members_are_visible_to_reads_and_calls() {
    check_console(
        r#"
const replacement = function (value) { return (this === Object) + ':' + value; };
Object.keys = replacement;
console.log(Object.keys === replacement, Object['keys'] === replacement);
console.log(Object.keys('called'));
JSON.parse = function (value) { return 'parse:' + value; };
Array.isArray = function () { return 'array'; };
String.fromCharCode = function () { return 'string'; };
Number.isInteger = function () { return 'number'; };
Reflect.ownKeys = function () { return 'reflect'; };
console.log(JSON.parse(1), Array.isArray([]), String.fromCharCode(65),
    Number.isInteger(1), Reflect.ownKeys({}));
"#,
        &[
            "true true",
            "true:called",
            "parse:1 array string number reflect",
        ],
    );
}

#[test]
fn saved_builtin_values_keep_their_original_behavior() {
    check_console(
        r#"
const keys = Object.keys;
const parse = JSON.parse;
const isArray = Array.isArray;
Object.keys = function () { return ['mock']; };
JSON.parse = function () { return 17; };
Array.isArray = function () { return false; };
console.log(keys({ original: 1 }).join(','), Object.keys({}).join(','));
console.log(parse('42'), JSON.parse('42'), isArray([]), Array.isArray([]));
"#,
        &["original mock", "42 17 true false"],
    );
}

#[test]
fn static_member_getters_run_before_arguments_with_the_correct_receiver() {
    check_console(
        r#"
let events = [];
Object.defineProperty(JSON, 'parse', {
    configurable: true,
    get() {
        if (this !== JSON) throw new Error('wrong getter receiver');
        events.push('get');
        return function (value) {
            if (this !== JSON) throw new Error('wrong call receiver');
            events.push('call');
            return value;
        };
    }
});
function argument() { events.push('arg'); return 'value'; }
console.log(JSON.parse(argument()), events.join(','));
"#,
        &["value get,arg,call"],
    );
}

#[test]
fn an_argument_replacing_the_member_does_not_replace_the_resolved_callee() {
    check_console(
        r#"
const first = function () { return 'first'; };
const second = function () { return 'second'; };
JSON.parse = first;
console.log(JSON.parse((JSON.parse = second, 'value')), JSON.parse('value'));
Object.keys = first;
function replace() { Object.keys = second; return []; }
console.log(Object.keys(...replace()), Object.keys({}));
"#,
        &["first second", "first second"],
    );
}

#[test]
fn static_member_getter_errors_prevent_argument_evaluation() {
    check_console(
        r#"
const token = {};
let ran = false;
Object.defineProperty(JSON, 'parse', {
    configurable: true,
    get() { throw token; }
});
try { JSON.parse((ran = true)); }
catch (error) { console.log(error === token, ran); }
"#,
        &["true false"],
    );
}

#[test]
fn noncallable_static_members_fail_after_evaluating_arguments() {
    check_console(
        r#"
Object.keys = 3;
let ran = false;
try { Object.keys((ran = true)); }
catch (error) { console.log(error instanceof TypeError, ran, Object.keys); }
"#,
        &["true true 3"],
    );
}

#[test]
fn deleted_and_inherited_static_members_use_the_property_chain() {
    check_console(
        r#"
console.log(delete Object.keys, typeof Object.keys, 'keys' in Object);
Object.setPrototypeOf(Object, {
    keys() { return this === Object ? 'inherited' : 'wrong receiver'; }
});
console.log(Object.keys({}), typeof Object.call);
Object.setPrototypeOf(Object, null);
console.log(Object.getPrototypeOf(Object) === null, Object.call === undefined,
    'keys' in Object);
console.log(delete JSON.parse, typeof JSON.parse);
"#,
        &[
            "true undefined false",
            "inherited undefined",
            "true true false",
            "true undefined",
        ],
    );
}

#[test]
fn static_member_calls_preserve_receiver_for_spread_and_nested_functions() {
    check_console(
        r#"
Object.is = function (left, right) { return (this === Object) + ':' + left + ':' + right; };
function run() { return Object.is(...[4, 5]); }
console.log(run());
String.fromCharCode = function (left, right) {
    return (this === String) + ':' + left + ':' + right;
};
console.log(String.fromCharCode?.(...[6, 7]));
"#,
        &["true:4:5", "true:6:7"],
    );
}

#[test]
fn static_member_descriptors_and_strict_writes_agree() {
    check_console(
        r#"
'use strict';
const replacement = function () { return 'defined'; };
Object.defineProperty(Object, 'keys', {
    value: replacement, writable: false, configurable: true
});
console.log(Object.keys === replacement, Object.keys({}));
try { Object.keys = function () { return 'wrong'; }; }
catch (error) { console.log(error instanceof TypeError); }
console.log(Object.getOwnPropertyDescriptor(Object, 'keys').value === Object.keys);
"#,
        &["true defined", "true", "true"],
    );
}

#[test]
fn static_builtins_used_only_inside_functions_keep_their_capability() {
    check_console(
        r#"
function run() {
    return Object.keys({ a: 1 }).join(',') + ':' + Number.isInteger(1) + ':' +
        String.fromCharCode(65) + ':' + Reflect.ownKeys({ b: 2 }).join(',');
}
console.log(run());
"#,
        &["a:true:A:b"],
    );
}

#[test]
fn replacing_reflect_apply_does_not_replace_the_internal_spread_operation() {
    check_console(
        r#"
const apply = Reflect.apply;
Reflect.apply = function () { return 'replacement'; };
const receiver = { sum(left, right) { return left + right; } };
console.log(receiver.sum(...[2, 3]),
    Reflect.apply(receiver.sum, receiver, [2, 3]),
    apply(receiver.sum, receiver, [2, 3]));
"#,
        &["5 replacement 5"],
    );
}

#[test]
fn static_member_loads_declare_builtin_authority_from_the_final_constant_pool() {
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser_api_stability::parse_script;

    for source in [
        "Number.isInteger(1);",
        "function check() { return Number.isInteger(1); } check();",
        "const keys = Object.keys; keys({ value: 1 });",
    ] {
        let tree = parse_script(source).expect("standard builtin source parses");
        let ir0 = Ir0Module::from_syntax_tree(tree, "mutable_static_authority.js");
        let context = LoweringContext::new("static-authority", "static-call", "builtin-policy");
        let lowered = lower_ir0_to_ir3(&ir0, &context).expect("standard builtin source lowers");
        assert!(
            lowered
                .ir3
                .required_capabilities
                .iter()
                .any(|tag| tag.0 == "builtin"),
            "runtime builtin value must declare its authority: {source}"
        );
    }
}
