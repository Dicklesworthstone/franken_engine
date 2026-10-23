//! Source-to-runtime regression coverage for mutable standard constructor and
//! namespace members (bd-9a8cz.2, bd-9vouw.293, bd-9vouw.366).
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
fn symbol_proxy_map_and_array_buffer_members_are_live_values() {
    check_console(
        r#"
const symbolFor = function (value) { return (this === Symbol) + ':' + value; };
Symbol.for = symbolFor;
Symbol.keyFor = function () { return 'key'; };
Proxy.revocable = function (value) { return (this === Proxy) + ':' + value; };
ArrayBuffer.isView = function (value) { return (this === ArrayBuffer) + ':' + value; };
Map.groupBy = function (value) { return (this === Map) + ':' + value; };
console.log(Symbol.for === symbolFor, Symbol['for'] === symbolFor);
console.log(Symbol.for('direct'), Symbol['for']('computed'), Symbol.keyFor(1));
console.log(Proxy.revocable('proxy'), ArrayBuffer.isView('view'), Map.groupBy('map'));
"#,
        &[
            "true true",
            "true:direct true:computed key",
            "true:proxy true:view true:map",
        ],
    );
}

#[test]
fn saved_symbol_proxy_map_and_array_buffer_intrinsics_keep_their_behavior() {
    check_console(
        r#"
const symbolFor = Symbol.for;
const symbolKeyFor = Symbol.keyFor;
const revocable = Proxy.revocable;
const isView = ArrayBuffer.isView;
const groupBy = Map.groupBy;
Symbol.for = function () { return 'replacement'; };
Symbol.keyFor = function () { return 'replacement'; };
Proxy.revocable = function () { return 'replacement'; };
ArrayBuffer.isView = function () { return 'replacement'; };
Map.groupBy = function () { return 'replacement'; };
console.log(symbolKeyFor(symbolFor('native')), isView(new Uint8Array(1)),
    groupBy([1, 2, 3], value => value % 2).get(1).join(','));
const pair = revocable({ value: 7 }, {});
console.log(pair.proxy.value);
pair.revoke();
try { pair.proxy.value; } catch (error) { console.log(error instanceof TypeError); }
console.log(Symbol.for('x'), Symbol.keyFor(1), Proxy.revocable({}, {}),
    ArrayBuffer.isView({}), Map.groupBy([]));
"#,
        &[
            "native true 1,3",
            "7",
            "true",
            "replacement replacement replacement replacement replacement",
        ],
    );
}

#[test]
fn additional_static_getters_preserve_receiver_and_evaluation_order() {
    check_console(
        r#"
const events = [];
function install(owner, name, label) {
    Object.defineProperty(owner, name, {
        configurable: true,
        get() {
            events.push(label + ':get:' + (this === owner));
            return function (value) {
                events.push(label + ':call:' + (this === owner));
                return value;
            };
        }
    });
}
function argument(value) { events.push('arg:' + value); return value; }
install(Symbol, 'for', 'symbol');
install(Proxy, 'revocable', 'proxy');
install(Map, 'groupBy', 'map');
install(ArrayBuffer, 'isView', 'buffer');
console.log(Symbol.for(argument(1)), Proxy.revocable(argument(2)),
    Map.groupBy(argument(3)), ArrayBuffer.isView(argument(4)));
console.log(events.join(','));
"#,
        &[
            "1 2 3 4",
            "symbol:get:true,arg:1,symbol:call:true,proxy:get:true,arg:2,proxy:call:true,map:get:true,arg:3,map:call:true,buffer:get:true,arg:4,buffer:call:true",
        ],
    );
}

#[test]
fn additional_static_members_capture_the_callee_before_spread_arguments() {
    check_console(
        r#"
function first(value) { return 'first:' + value; }
function second(value) { return 'second:' + value; }
Symbol.for = first;
Proxy.revocable = first;
Map.groupBy = first;
ArrayBuffer.isView = first;
function replace(owner, key, value) { owner[key] = second; return [value]; }
function run() {
    return [
        Symbol.for(...replace(Symbol, 'for', 1)),
        Proxy.revocable(...replace(Proxy, 'revocable', 2)),
        Map.groupBy(...replace(Map, 'groupBy', 3)),
        ArrayBuffer.isView(...replace(ArrayBuffer, 'isView', 4))
    ].join(',');
}
console.log(run());
console.log(Symbol.for(1), Proxy.revocable(2), Map.groupBy(3), ArrayBuffer.isView(4));
Map.groupBy = function (left, right) { return (this === Map) + ':' + left + ':' + right; };
console.log(Map.groupBy?.(...[5, 6]));
"#,
        &[
            "first:1,first:2,first:3,first:4",
            "second:1 second:2 second:3 second:4",
            "true:5:6",
        ],
    );
}

#[test]
fn additional_static_members_honor_deletion_and_inheritance() {
    check_console(
        r#"
console.log(delete Symbol.for, typeof Symbol.for,
    delete Proxy.revocable, typeof Proxy.revocable,
    delete Map.groupBy, typeof Map.groupBy,
    delete ArrayBuffer.isView, typeof ArrayBuffer.isView);
Object.setPrototypeOf(Symbol, { for(value) { return (this === Symbol) + ':' + value; } });
Object.setPrototypeOf(Proxy, { revocable(value) { return (this === Proxy) + ':' + value; } });
Object.setPrototypeOf(Map, { groupBy(value) { return (this === Map) + ':' + value; } });
Object.setPrototypeOf(ArrayBuffer, { isView(value) { return (this === ArrayBuffer) + ':' + value; } });
console.log(Symbol.for('symbol'), Proxy.revocable('proxy'),
    Map.groupBy('map'), ArrayBuffer.isView('buffer'));
"#,
        &[
            "true undefined true undefined true undefined true undefined",
            "true:symbol true:proxy true:map true:buffer",
        ],
    );
}

#[test]
fn additional_static_getter_and_noncallable_errors_keep_argument_order() {
    check_console(
        r#"
let ran = false;
const token = {};
Object.defineProperty(Symbol, 'for', { configurable: true, get() { throw token; } });
try { Symbol.for((ran = true)); }
catch (error) { console.log(error === token, ran); }
Proxy.revocable = 1;
try { Proxy.revocable((ran = true)); }
catch (error) { console.log(error instanceof TypeError, ran); }
ran = false;
delete Map.groupBy;
try { Map.groupBy((ran = true)); }
catch (error) { console.log(error instanceof TypeError, ran); }
Object.defineProperty(ArrayBuffer, 'isView', { value: 2, writable: false });
function strictWrite() { 'use strict'; ArrayBuffer.isView = 3; }
try { strictWrite(); }
catch (error) { console.log(error instanceof TypeError, ArrayBuffer.isView); }
"#,
        &["true false", "true true", "true true", "true 2"],
    );
}

#[test]
fn additional_static_constructor_shadows_remain_ordinary_user_objects() {
    check_console(
        r#"
function run(Symbol, Proxy, Map, ArrayBuffer) {
    return [Symbol.for(1), Proxy.revocable(2), Map.groupBy(3), ArrayBuffer.isView(4)].join(',');
}
const Symbol = { for(value) { return this.prefix + value; }, prefix: 's' };
const Proxy = { revocable(value) { return this.prefix + value; }, prefix: 'p' };
const Map = { groupBy(value) { return this.prefix + value; }, prefix: 'm' };
const ArrayBuffer = { isView(value) { return this.prefix + value; }, prefix: 'a' };
console.log(run(Symbol, Proxy, Map, ArrayBuffer));
"#,
        &["s1,p2,m3,a4"],
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
        "Symbol.for('native');",
        "function check() { return Symbol.keyFor(Symbol.for('native')); } check();",
        "const revocable = Proxy.revocable; revocable({}, {});",
        "function check() { return Map.groupBy([], value => value); } check();",
        "ArrayBuffer.isView({});",
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

#[test]
fn mutable_constructor_native_calls_still_require_builtin_authority() {
    use frankenengine_engine::baseline_interpreter::{
        InterpreterConfig, InterpreterError, QuickJsLane,
    };
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser_api_stability::parse_script;

    for (source, expected_capability) in [
        ("Symbol.for('native');", "builtin:SymbolFor"),
        ("Symbol.keyFor(undefined);", "builtin:SymbolKeyFor"),
        ("Proxy.revocable({}, {});", "builtin:ProxyRevocable"),
        ("Map.groupBy([], value => value);", "builtin:MapGroupBy"),
        ("ArrayBuffer.isView({});", "builtin:ArrayBufferIsView"),
    ] {
        let tree = parse_script(source).expect("native constructor member source parses");
        let ir0 = Ir0Module::from_syntax_tree(tree, "mutable_native_authority.js");
        let context = LoweringContext::new("native-authority", "native-call", "builtin-policy");
        let lowered = lower_ir0_to_ir3(&ir0, &context).expect("native member source lowers");
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]
        .into_iter()
        .collect();
        let error = QuickJsLane::with_config(config)
            .execute(&lowered.ir3, "native-authority")
            .expect_err("a live native member must still enforce its invocation authority");
        assert!(
            matches!(error, InterpreterError::CapabilityDenied { ref capability }
                if capability == expected_capability),
            "{source}: expected denial of {expected_capability}, got {error:?}"
        );
    }
}

#[test]
fn replaced_constructor_members_do_not_hide_sensitive_callback_results() {
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{
        LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
    };
    use frankenengine_engine::parser_api_stability::parse_script;

    for member in [
        "Symbol.for",
        "Symbol.keyFor",
        "Proxy.revocable",
        "Map.groupBy",
        "ArrayBuffer.isView",
    ] {
        let source = format!(
            "const secret = hostcall('random_read'); \
             {member} = function () {{ return secret; }}; console.log({member}('input'));"
        );
        let tree = parse_script(&source).expect("sensitive replacement source parses");
        let ir0 = Ir0Module::from_syntax_tree(tree, "mutable_static_sensitive_result.js");
        let context = LoweringContext::new("static-flow", "patched-call", "secret-policy");
        let error = lower_ir0_to_ir3(&ir0, &context)
            .expect_err("a replaced member can return its captured sensitive value");
        assert!(
            matches!(error, LoweringPipelineError::UnauthorizedFlow {
                ref source_label,
                sink_clearance: Label::Internal,
                ..
            } if *source_label >= Label::Secret),
            "{member}: expected a sensitive callback result to be denied, got {error:?}"
        );
    }
}
