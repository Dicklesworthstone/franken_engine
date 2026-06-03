//! Regression for bd-hsv77: spread in call arguments. `f(...xs)` passed the
//! whole array as arg 0 (a=[1,2,3], b/c=undefined → NaN) because the Call
//! lowering counted a SpreadElement as one positional arg. Fix: for a plain
//! (non-member) call with any spread arg, assemble the real argument list into
//! an array and dispatch via builtin:ReflectApply(target, undefined, argsArray).
//! Scope: free calls (the bead's pins); member-call spread `obj.m(...xs)` and
//! builtin spread `Math.max(...xs)` remain follow-ups.
use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => format!("{}", o.value),
        Err(err) => format!("ERR={}", err.to_string().lines().next().unwrap_or("")),
    }
}

#[test]
fn spread_array_literal() {
    assert_eq!(eval("let f = (a,b,c) => a+b+c; f(...[1,2,3]);"), "6");
}

#[test]
fn spread_variable() {
    assert_eq!(eval("let f = (a,b,c) => a+b+c; let xs = [1,2,3]; f(...xs);"), "6");
}

#[test]
fn spread_mixed_leading_and_trailing() {
    // leading fixed arg + spread
    assert_eq!(eval("let f = (a,b,c) => a+b+c; f(0, ...[1,2]);"), "3");
    // spread + trailing fixed arg
    assert_eq!(eval("let f = (a,b,c) => a+b+c; f(...[1,2], 3);"), "6");
}

#[test]
fn spread_empty() {
    assert_eq!(eval("let f = (a) => typeof a; f(...[]);"), "undefined");
}

#[test]
fn regular_calls_unaffected_no_blast_radius() {
    // The fix must NOT change non-spread calls (the high-blast-radius concern).
    assert_eq!(eval("let f = (a,b) => a + b; f(2, 3);"), "5");
    assert_eq!(eval("let g = (a,b,c) => a*100 + b*10 + c; g(1,2,3);"), "123");
    // builtin call still routes through its hostcall, not the spread path
    assert_eq!(eval("Math.max(1, 5, 3);"), "5");
    // method call still binds `this` / dispatches normally
    assert_eq!(eval("let o = { m(x) { return x * 2; } }; o.m(4);"), "8");
}
