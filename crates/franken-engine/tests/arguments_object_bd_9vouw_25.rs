//! bd-9vouw.25: non-arrow functions have an `arguments` object (ES2020
//! 9.4.4): every actual argument (not just declared
//! parameters), a non-enumerable `length`, and arrows see their enclosing
//! function's object.
//!
//! Before this, every read threw "arguments is not defined", which also
//! stopped the Test262 propertyHelper.js `verifyProperty` (it opens with
//! `assert(arguments.length > 2, ...)`). Expected strings are what Node
//! v22.2.0 prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.
//! bd-9vouw.281 additionally covers the live parameter map of sloppy
//! functions with simple parameters, including its descriptor transitions.

use frankenengine_engine::HybridRouter;

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

#[test]
fn sloppy_arguments_and_parameters_share_values_bd_9vouw_281() {
    check(
        "function f(a) { a = 2; var first = arguments[0]; arguments[0] = 3; \
         return first + ':' + a + ':' + Object.getOwnPropertyDescriptor(arguments, '0').value; } f(1);",
        "2:3:3",
    );
    check(
        "function f(a) { a += 4; arguments[0]++; ++a; return a + ':' + arguments[0]; } f(1);",
        "7:7",
    );
    check(
        "function f(a) { var a = 8; return arguments[0] + ':' + a; } f(1);",
        "8:8",
    );
    check(
        "function f(a) { function a() {} return typeof arguments[0] + ':' + \
         (a === arguments[0]); } f(1);",
        "function:true",
    );
    check(
        "var outer = 10; function f(a) { a += outer; arguments[0]++; \
         return a + ':' + arguments[0]; } f(1);",
        "12:12",
    );
    check(
        "var o = { f(a) { arguments[0] = 7; return a; } }; o.f(1);",
        "7",
    );
}

#[test]
fn mapped_arguments_handle_duplicate_missing_and_extra_parameters_bd_9vouw_281() {
    check(
        "function f(a, a) { a = 3; var first = arguments[0] + ':' + arguments[1]; \
         arguments[0] = 4; var middle = a; arguments[1] = 5; return first + ':' + middle + ':' + a; } f(1, 2);",
        "1:3:3:5",
    );
    check(
        "function f(a, a) { var initial = String(a); a = 3; var first = arguments[0]; \
         arguments[0] = 9; return initial + ':' + first + ':' + a; } f(1);",
        "undefined:1:3",
    );
    check(
        "function f(a, b) { b = 4; var absent = Object.prototype.hasOwnProperty.call(arguments, '1'); \
         arguments[1] = 8; return absent + ':' + b + ':' + arguments.length; } f(1);",
        "false:4:1",
    );
    check(
        "function f(a) { arguments[1] = 9; a = 4; return arguments.length + ':' + \
         Array.prototype.join.call(arguments, ','); } f(1, 2, 3);",
        "3:4,9,3",
    );
}

#[test]
fn mapped_arguments_survive_return_and_share_captured_parameter_cells_bd_9vouw_281() {
    check(
        "function f(a) { return [arguments, () => a, value => a = value]; } \
         var escaped = f(1); escaped[2](7); var first = escaped[0][0]; escaped[0][0] = 9; \
         first + ':' + escaped[1]();",
        "7:9",
    );
    check(
        "function f(a) { var args = arguments; return function () { a++; \
         return function () { args[0]++; return a; }; }; } f(1)()();",
        "3",
    );
    check(
        "function f(a) { var read = () => a; var args = arguments; arguments = null; \
         args[0] = 6; return read(); } f(1);",
        "6",
    );
}

#[test]
fn mapped_argument_data_descriptors_update_or_disconnect_the_cell_bd_9vouw_281() {
    check(
        "function f(a) { Object.defineProperty(arguments, '0', { value: 7 }); \
         var first = a; a = 8; var d = Object.getOwnPropertyDescriptor(arguments, '0'); \
         return first + ':' + d.value + ':' + d.writable + ':' + d.enumerable + ':' + d.configurable; } f(1);",
        "7:8:true:true:true",
    );
    check(
        "function f(a) { a = 6; Object.defineProperty(arguments, '0', { writable: false }); \
         a = 8; return arguments[0] + ':' + a + ':' + Object.getOwnPropertyDescriptor(arguments, '0').value; } f(1);",
        "6:8:6",
    );
    check(
        "function f(a) { Object.defineProperty(arguments, '0', { value: 9, writable: false }); \
         var first = a; a = 10; Object.defineProperty(arguments, '0', { writable: true }); \
         arguments[0] = 11; return first + ':' + a + ':' + arguments[0]; } f(1);",
        "9:10:11",
    );
}

#[test]
fn mapped_argument_accessors_and_deletion_disconnect_permanently_bd_9vouw_281() {
    check(
        "function f(a) { Object.defineProperty(arguments, '0', { get: function () { return 99; } }); \
         a = 3; return a + ':' + arguments[0]; } f(1);",
        "3:99",
    );
    check(
        "function f(a) { var written = 0; Object.defineProperty(arguments, '0', \
         { set: function (value) { written = value; } }); arguments[0] = 7; \
         return a + ':' + written + ':' + String(arguments[0]); } f(1);",
        "1:7:undefined",
    );
    check(
        "function f(a) { var deleted = delete arguments[0]; a = 2; var absent = String(arguments[0]); \
         arguments[0] = 7; a = 8; return deleted + ':' + absent + ':' + a + ':' + arguments[0]; } f(1);",
        "true:undefined:8:7",
    );
    check(
        "function f(a) { Object.defineProperty(arguments, '0', { configurable: false }); \
         var removed = Reflect.deleteProperty(arguments, '0'); \
         var changed = Reflect.defineProperty(arguments, '0', { get: function () { return 99; } }); \
         a = 2; var first = arguments[0]; arguments[0] = 3; \
         return removed + ':' + changed + ':' + first + ':' + a; } f(1);",
        "false:false:2:3",
    );
}

#[test]
fn sealing_preserves_mapping_and_freezing_takes_current_values_bd_9vouw_281() {
    check(
        "function f(a) { Object.seal(arguments); a = 2; var first = arguments[0]; \
         arguments[0] = 3; return first + ':' + a + ':' + Object.isSealed(arguments); } f(1);",
        "2:3:true",
    );
    check(
        "function f(a) { a = 4; Object.freeze(arguments); a = 5; arguments[0] = 6; \
         return arguments[0] + ':' + a + ':' + Object.isFrozen(arguments); } f(1);",
        "4:5:true",
    );
}

#[test]
fn mapped_arguments_respect_receivers_and_proxy_forwarding_bd_9vouw_281() {
    check(
        "function f(a) { var receiver = {}; var ok = Reflect.set(arguments, '0', 7, receiver); \
         return ok + ':' + a + ':' + arguments[0] + ':' + receiver[0]; } f(1);",
        "true:1:1:7",
    );
    check(
        "function f(a) { var proxy = new Proxy(arguments, {}); proxy[0] = 7; \
         var first = a; a = 8; return first + ':' + proxy[0] + ':' + \
         Object.getOwnPropertyDescriptor(proxy, '0').value; } f(1);",
        "7:8:8",
    );
    check(
        "function f(a) { var proxy = new Proxy(arguments, {}); \
         Reflect.set(arguments, '0', 7, proxy); var first = a; \
         Object.defineProperty(proxy, '0', { value: 8, writable: false }); \
         var second = a; a = 9; return first + ':' + second + ':' + arguments[0] + ':' + a; } f(1);",
        "7:8:8:9",
    );
}

#[test]
fn strict_and_non_simple_arguments_stay_unmapped_bd_9vouw_281() {
    check(
        "function f(a) { 'use strict'; a = 2; var first = arguments[0]; \
         arguments[0] = 3; return first + ':' + a; } f(1);",
        "1:2",
    );
    check(
        "function f(a = 0) { a = 2; var first = arguments[0]; arguments[0] = 3; \
         return first + ':' + a; } f(1);",
        "1:2",
    );
    check(
        "function f(a, ...rest) { a = 2; var first = arguments[0]; arguments[0] = 3; \
         return first + ':' + a + ':' + rest[0]; } f(1, 4);",
        "1:2:4",
    );
    check(
        "function f([a]) { a = 2; arguments[0] = [3]; return a; } f([1]);",
        "2",
    );
    check(
        "class C { f(a) { a = 2; var first = arguments[0]; arguments[0] = 3; \
         return first + ':' + a; } } new C().f(1);",
        "1:2",
    );
}

#[test]
fn every_mapped_call_path_initializes_its_own_parameter_map_bd_9vouw_281() {
    check(
        "function f(a) { a++; return arguments[0]; } \
         [f.call(null, 1), f.apply(null, [2]), f.bind(null, 3)()].join();",
        "2,3,4",
    );
    check(
        "function C(a) { arguments[0] = 7; this.value = a; } new C(1).value;",
        "7",
    );
    check(
        "function* f(a) { yield arguments; a++; yield arguments[0]; } \
         var it = f(1); var args = it.next().value; args[0] = 7; \
         it.next().value + ':' + args[0];",
        "8:8",
    );
}

#[test]
fn async_arguments_remain_mapped_across_suspension_bd_9vouw_281() {
    let outcome = HybridRouter::default()
        .eval(
            "async function f(a) { var args = arguments; await 0; args[0] = 7; return a; } \
               f(1).then(function (value) { console.log(value); });",
        )
        .expect("async mapped arguments execute");
    assert_eq!(
        outcome
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect::<Vec<_>>(),
        ["7"],
    );
}

#[test]
fn arguments_holds_every_actual_argument() {
    check("function f() { return arguments.length; } f(1, 2, 3);", "3");
    check(
        "function f(a) { return arguments[1] + arguments.length; } f(1, 10);",
        "12",
    );
    // Fewer arguments than parameters: length counts actual arguments.
    check("function f(a, b) { return arguments.length; } f(1);", "1");
    check(
        "function f() { return Array.prototype.slice.call(arguments).join('-'); } f('a', 'b');",
        "a-b",
    );
    check("function f() { return typeof arguments; } f();", "object");
}

/// A generator's body runs at its first `next()`, after the call that only
/// created the generator; no call setup staged its arguments object, so
/// the body saw an empty one (Test262 arguments-object/
/// gen-meth-args-trailing-comma-multiple and relatives).
#[test]
fn generator_bodies_see_their_invocation_arguments() {
    check(
        "var o = { *g() { yield arguments.length; yield arguments[1]; } }; \
         var it = o.g(1, 'x',); [it.next().value, it.next().value].join();",
        "2,x",
    );
    check(
        "class C { *m() { yield arguments.length; } static *s() { yield arguments.length; } } \
         [new C().m(1, 2, 3).next().value, C.s(1).next().value].join();",
        "3,1",
    );
    check(
        "function* g2(a) { return arguments.length + ':' + a; } g2(1, 2).next().value;",
        "2:1",
    );
    check(
        "function* g3() { yield 1; yield arguments[0]; } var it3 = g3('late'); it3.next(); \
         it3.next().value;",
        "late",
    );
    check(
        "function* g4(a, ...r) { yield arguments.length + ':' + r.length; } \
         g4(1, 2, 3).next().value;",
        "3:2",
    );
}

#[test]
fn length_is_not_enumerable() {
    check(
        "function f() { var ks = []; for (var k in arguments) ks.push(k); return ks.join(); } \
         f('x', 'y');",
        "0,1",
    );
}

#[test]
fn every_call_path_stages_arguments() {
    check(
        "var o = { m: function () { return arguments.length; } }; o.m(1, 2);",
        "2",
    );
    check(
        "var n = 0; [1].forEach(function () { n = arguments.length; }); n;",
        "3",
    );
    check(
        "function C() { this.n = arguments.length; } new C(1, 2).n;",
        "2",
    );
    check(
        "function f() { return arguments.length; } f.apply(null, [1, 2, 3, 4]);",
        "4",
    );
    check(
        "class C { m() { return arguments.length; } } new C().m(1, 2, 3);",
        "3",
    );
    check(
        "function outer() { function inner() { return arguments.length; } \
         return inner(1) + ':' + arguments.length; } outer(1, 2);",
        "1:2",
    );
}

#[test]
fn arrows_use_the_enclosing_arguments_and_bindings_shadow() {
    check(
        "function f() { var g = () => arguments[0]; return g(); } f(7);",
        "7",
    );
    check(
        "function f() { var arguments = 5; return arguments; } f(1);",
        "5",
    );
    // A function with free variables pushes its scope before declaring it.
    check(
        "var captured = 'x'; function f() { return captured + arguments[0]; } f('y');",
        "xy",
    );
}

// bd-9vouw.372: every non-arrow invocation owns its arguments binding;
// ordinary var redeclarations and arrow captures must keep that binding's identity.

#[test]
fn each_non_arrow_function_owns_arguments_despite_outer_source_bindings() {
    check(
        "var arguments = 'outer'; function f() { return arguments[0] + ':' + arguments.length; \
         } f('inner', 2);",
        "inner:2",
    );
    check(
        "let arguments = 'outer'; const f = function () { return arguments[0]; }; \
         f('expression');",
        "expression",
    );
    check(
        "var arguments = 'outer'; var o = { m() { return arguments[0]; } }; o.m('method');",
        "method",
    );
    check(
        "function outer(arguments) { return function () { return arguments[0]; }; } \
         outer('outer')('inner');",
        "inner",
    );
    check(
        "var arguments = 'outer'; function* g() { yield arguments[0]; } \
         g('generator').next().value;",
        "generator",
    );
    check(
        "var arguments = 'outer'; class C { constructor() { this.x = arguments[0]; } m() { \
         return arguments[0]; } } var c = new C('ctor'); c.x + ':' + c.m('method');",
        "ctor:method",
    );
    check(
        "var arguments = 'outer'; var C = class { constructor() { this.x = arguments[0]; } m() \
         { return arguments[0]; } }; var c = new C('ctor'); c.x + ':' + c.m('method');",
        "ctor:method",
    );
    check(
        "var f = function arguments() { return arguments[0]; }; f('own');",
        "own",
    );
}

#[test]
fn var_arguments_redeclarations_preserve_the_entry_object() {
    check(
        "function f() { return typeof arguments; var arguments = 1; } f('x');",
        "object",
    );
    check(
        "function f() { var arguments; return arguments[0]; } f('kept');",
        "kept",
    );
    check(
        "function f() { if (false) { var arguments; } return arguments[0]; } f('block');",
        "block",
    );
    check(
        "function f() { var arguments = 7; var arguments; return arguments; } f(1);",
        "7",
    );
    check(
        "function f() { var [arguments] = [8]; return arguments; } f(1);",
        "8",
    );
    check(
        "function f() { var n = arguments.length; var arguments = 9; return n + ':' + \
         arguments; } f(1, 2);",
        "2:9",
    );
    check(
        "function f() { arguments = 6; var arguments; return arguments; } f();",
        "6",
    );
}

#[test]
fn arrows_and_their_parent_share_the_arguments_binding() {
    check(
        "function f() { const g = () => arguments; arguments = 7; return g(); } f(1);",
        "7",
    );
    check(
        "function f() { const g = () => { arguments = 8; }; g(); return arguments; } f(1);",
        "8",
    );
    check(
        "function f() { const g = () => () => arguments; const h = g(); arguments = 9; return \
         h(); } f(1);",
        "9",
    );
    check(
        "function f() { const g = () => () => { arguments = 10; }; g()(); return arguments; } \
         f(1);",
        "10",
    );
    check(
        "function f() { const g = () => arguments; var arguments = 11; return g(); } f(1);",
        "11",
    );
    check(
        "function f() { let g; { let arguments = 'block'; g = () => arguments; } return g() + \
         ':' + arguments[0]; } f('own');",
        "block:own",
    );
    check(
        "var arguments = 'outer'; const g = () => arguments; function f() { return (() => \
         arguments[0])(); } g() + ':' + f('own');",
        "outer:own",
    );
    check(
        "function f() { const g = arguments => () => arguments; return g('arrow')() + ':' + \
         arguments[0]; } f('own');",
        "arrow:own",
    );
}

#[test]
fn parameter_and_function_declarations_still_shadow_arguments() {
    check(
        "function f(arguments) { var arguments; return arguments; } f('parameter');",
        "parameter",
    );
    check(
        "function f({ arguments }) { return arguments; } f({ arguments: 'destructured' });",
        "destructured",
    );
    check(
        "function f(arguments = 'default') { return arguments; } f();",
        "default",
    );
    check(
        "function f() { return arguments(); function arguments() { return 'declaration'; } } \
         f(1);",
        "declaration",
    );
    check(
        "function f() { let arguments = 'lexical'; return arguments; } f(1);",
        "lexical",
    );
    check(
        "function f() { const g = (arguments) => arguments; return g('arrow') + ':' + \
         arguments[0]; } f('own');",
        "arrow:own",
    );
}

#[test]
fn parameter_defaults_resolve_the_functions_own_arguments() {
    check(
        "var arguments = 'outer'; function f(a = arguments[1]) { return a; } f(undefined, \
         'default');",
        "default",
    );
    check(
        "var arguments = 'outer'; function f({ a = arguments[1] } = {}) { return a; } \
         f(undefined, 'destructured');",
        "destructured",
    );
    check(
        "function f(read = () => arguments) { return read()[1]; } f(undefined, 'arrow');",
        "arrow",
    );
    check(
        "function f(a = arguments[1]) { function arguments() { return 'body'; } return a + ':' \
         + arguments(); } f(undefined, 'default');",
        "default:body",
    );
    check(
        "var arguments = 'outer'; function f(read = () => arguments) { return read()[1]; } \
         f(undefined, 'own');",
        "own",
    );
    check(
        "function f(read = () => arguments) { arguments = 7; return read(); } f();",
        "7",
    );
    check(
        "function f(change = () => { arguments = 8; }) { change(); return arguments; } f();",
        "8",
    );
    check(
        "function f(value = (arguments = 9)) { return arguments + ':' + value; } f();",
        "9:9",
    );
}

#[test]
fn body_var_arguments_preserves_the_parameter_environment() {
    check(
        "function f(a = 1) { var arguments; return arguments[1]; } f(undefined, 'body');",
        "body",
    );
    check(
        "function f(read = () => arguments) { var arguments = 7; return read()[1] + ':' + \
         arguments; } f(undefined, 'parameter');",
        "parameter:7",
    );
    check(
        "function f(read = () => arguments) { var arguments; const change = () => { arguments \
         = 8; }; change(); return read()[1] + ':' + arguments; } f(undefined, 'parameter');",
        "parameter:8",
    );
    check(
        "function f(value = (arguments = 9)) { var arguments; return arguments + ':' + value; \
         } f();",
        "9:9",
    );
    check(
        "function f(read = () => arguments) { var arguments; const same = () => arguments; \
         arguments = 7; return same() + ':' + read()[1]; } f(undefined, 'parameter');",
        "7:parameter",
    );
    check(
        "function f(read = () => arguments) { var arguments; arguments[1] = 'changed'; return \
         read()[1]; } f(undefined, 'parameter');",
        "changed",
    );
    check(
        "function f(read = () => arguments) { var arguments; const old = read(); arguments = \
         7; return old === read(); } f();",
        "true",
    );
    check(
        "function f(read = () => arguments) { let arguments = 'body'; return read()[1] + ':' + \
         arguments; } f(undefined, 'parameter');",
        "parameter:body",
    );
    check(
        "function f(change = () => { arguments = 11; }, read = () => arguments) { var \
         arguments; change(); return typeof arguments + ':' + read(); } f();",
        "object:11",
    );
    check(
        "function* f(read = () => arguments) { var arguments = 7; yield read()[1] + ':' + \
         arguments; } f(undefined, 'parameter').next().value;",
        "parameter:7",
    );
}

#[test]
fn generator_body_arguments_is_instantiated_before_the_first_resume() {
    check(
        "var change; function* g(x = (change = () => { arguments = 17; })) { var arguments; \
         yield typeof arguments; } var it = g(); change(); it.next().value;",
        "object",
    );
    check(
        "var change; const g = function* (x = (change = () => { arguments = 23; })) { var \
         arguments; yield typeof arguments; }; const it = g(); change(); it.next().value;",
        "object",
    );
}
