//! Regression: default and destructuring parameters in arrow functions and
//! function expressions must bind their value (and apply defaults), not be
//! silently dropped.
//!
//! Bead: bd-f2iw8. ROOT CAUSE (IR-dump-pinned): the arrow-function and
//! function-expression lowering built `param_names` with
//! `params.iter().filter_map(|p| p.name())`. `FunctionParam::name()` returns
//! `None` for any non-identifier pattern (a default `x = v` parses as
//! `AssignmentPattern`, destructuring as Object/ArrayPattern), so `filter_map`
//! silently DROPPED those params — the function ended up arity 0 with the
//! argument value lost, so `((x = 5) => x)()` (and even `(9)`) returned
//! `undefined`. The function-*declaration* path already handled this via a
//! synthetic `__param_N` slot + `lower_destructuring_to_ir1` (which applies the
//! default); the two expression paths did not.
//!
//! FIX: give non-identifier params a synthetic slot and destructure them at
//! body entry in both the arrow and function-expression paths.
//!
//! (Class constructor/method params share the same `filter_map` bug — tracked
//! separately under the sibling bead, different lowering context.)

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn arrow_default_param_applied_when_arg_missing() {
    assert_eq!(eval_value("let f = (x = 5) => x; f();"), "5");
}

#[test]
fn arrow_default_param_overridden_when_arg_supplied() {
    assert_eq!(eval_value("let f = (x = 5) => x; f(9);"), "9");
}

#[test]
fn arrow_multiple_defaults() {
    assert_eq!(eval_value("let f = (a = 1, b = 2) => a + b; f();"), "3");
}

#[test]
fn arrow_default_initializer_expression() {
    assert_eq!(eval_value("let f = (x = 3 + 4) => x; f();"), "7");
}

#[test]
fn function_expression_default_param_applied() {
    assert_eq!(
        eval_value("let f = function (x = 5) { return x; }; f();"),
        "5"
    );
}

#[test]
fn function_declaration_default_still_works() {
    // Guard: the declaration path already worked; the fix must not regress it.
    assert_eq!(eval_value("function f(x = 5) { return x; } f();"), "5");
}

#[test]
fn arrow_array_destructuring_param() {
    assert_eq!(eval_value("let f = ([a, b]) => a + b; f([3, 4]);"), "7");
}

#[test]
fn arrow_object_destructuring_param() {
    assert_eq!(eval_value("let f = ({ x }) => x; f({ x: 9 });"), "9");
}

#[test]
fn function_declaration_whole_object_pattern_default_applies_before_destructuring() {
    assert_eq!(
        eval_value("function f({a = 5} = {}) { return a; } f();"),
        "5"
    );
}

#[test]
fn arrow_whole_array_pattern_default_applies_before_destructuring() {
    assert_eq!(eval_value("let f = ([a = 7] = []) => a; f();"), "7");
}

#[test]
fn parameter_defaults_capture_outer_binding_before_body_shadow_bd_4thqe() {
    let cases = [
        (
            "function declaration",
            "const x = 42; function f(a = x) { let x = 7; return a; } f();",
        ),
        (
            "arrow function",
            "const x = 42; let f = (a = x) => { let x = 7; return a; }; f();",
        ),
        (
            "function expression",
            "const x = 42; let f = function (a = x) { let x = 7; return a; }; f();",
        ),
    ];

    for (form, source) in cases {
        assert_eq!(eval_value(source), "42", "{form}");
    }
}

#[test]
fn parameter_defaults_honor_outer_static_global_shadows_bd_4thqe() {
    let cases = [
        "const Math = { abs: n => n + 40 }; function f(v = Math.abs(2)) { return v; } f();",
        "const Math = { abs: n => n + 40 }; let f = (v = Math.abs(2)) => v; f();",
        "const Math = { abs: n => n + 40 }; let f = function (v = Math.abs(2)) { return v; }; f();",
    ];

    for source in cases {
        assert_eq!(eval_value(source), "42");
    }
}

#[test]
fn parameter_environment_keeps_body_bindings_out_of_defaults_bd_4thqe() {
    assert_eq!(
        eval_value("function f(v = Math.abs(-5)) { let Math = { abs: () => 99 }; return v; } f();"),
        "5"
    );
    assert_eq!(
        eval_value(
            "const x = 42; function f({ value = x } = {}) { let x = 7; return value; } f();"
        ),
        "42"
    );
    assert_eq!(
        eval_value("const a = 99; function f(a = 3, b = a) { return b; } f();"),
        "3"
    );
    assert_eq!(
        eval_value("const x = 42; function f(a = x) { if (true) { var x = 7; } return a; } f();"),
        "42"
    );
}

#[test]
fn parameter_default_capture_crosses_an_intermediate_function_bd_4thqe() {
    assert_eq!(
        eval_value(
            "const x = 42;\
             function outer() {\
                 return function inner(a = x) { let x = 7; return a; };\
             }\
             outer()();"
        ),
        "42"
    );
}

#[test]
fn parameter_runtime_globals_survive_same_named_body_bindings_bd_4thqe() {
    assert_eq!(
        eval_value(
            "function f(a = typeof performance, b = typeof console, c = typeof Function) {\
                 let performance = 0; let console = 0; let Function = 0;\
                 return a + ':' + b + ':' + c;\
             } f();"
        ),
        "object:object:function"
    );
}

#[test]
fn parameter_default_closure_retains_earlier_parameter_capture_bd_4thqe() {
    assert_eq!(
        eval_value("function f(a = 3, g = () => a) { return g; } let g = f(); g();"),
        "3"
    );
}

#[test]
fn missing_parameter_default_is_not_hidden_by_body_binding_bd_4thqe() {
    assert_eq!(
        eval_value(
            "try {\
                 function f(a = missing) { let missing = 1; return a; }\
                 f();\
             } catch (error) { error.name; }"
        ),
        "ReferenceError"
    );
}

#[test]
fn named_function_expression_self_is_visible_to_its_default_bd_4thqe() {
    assert_eq!(
        eval_value(
            "let Inner = 7;\
             let F = function Inner(v = Inner) { let Inner = 9; return v; };\
             let G = F; F = 0; G() === G && Inner === 7;"
        ),
        "true"
    );
}
