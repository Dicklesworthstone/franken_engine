//! bd-hsv77 — spread in call arguments expands into positional args.
//!
//! `f(...xs)` previously passed the whole array as one positional arg (so
//! `(a,b,c)=>a+b+c` saw a=[1,2,3], b/c undefined → NaN). The Call lowering now
//! detects a spread argument on a free (non-member) callee and dispatches via
//! `builtin:ReflectApply(f, undefined, argsArray)`, building the argument array
//! with the array-literal spread machinery (so mixed `f(0,...xs,1)` works).

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn spread_array_literal_into_call() {
    assert_eq!(eval("let f = (a, b, c) => a + b + c; f(...[1, 2, 3]);"), "6");
}

#[test]
fn spread_variable_into_call() {
    assert_eq!(
        eval("let f = (a, b, c) => a + b + c; let xs = [1, 2, 3]; f(...xs);"),
        "6"
    );
}

#[test]
fn leading_fixed_arg_then_spread() {
    assert_eq!(eval("let f = (a, b, c) => a + b + c; f(0, ...[1, 2]);"), "3");
}

#[test]
fn spread_between_fixed_args() {
    assert_eq!(
        eval("let f = (a, b, c, d) => a + b + c + d; f(1, ...[2, 3], 4);"),
        "10"
    );
}

#[test]
fn two_element_spread() {
    assert_eq!(eval("let f = (a, b) => a + b; f(...[10, 20]);"), "30");
}

#[test]
fn no_spread_call_unchanged() {
    assert_eq!(eval("let f = (a, b) => a + b; f(4, 5);"), "9");
}
