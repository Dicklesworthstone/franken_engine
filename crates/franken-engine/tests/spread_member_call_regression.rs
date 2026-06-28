#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => outcome.value.to_string(),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn math_static_member_call_spread_expands_arguments() {
    assert_eq!(eval("Math.max(...[1, 9, 3]);"), "9");
}

#[test]
fn math_static_member_call_spread_preserves_argument_order() {
    assert_eq!(eval("Math.max(1, ...[9, 3], 4);"), "9");
}

#[test]
fn user_method_spread_evaluates_receiver_once_and_preserves_this() {
    assert_eq!(
        eval(
            "let state = { calls: 0 }; \
             function getObj() { \
               state.calls = state.calls + 1; \
               return { base: 10, add(a, b) { return this.base + a + b; } }; \
             } \
             let xs = [2, 3]; \
             getObj().add(...xs) + state.calls * 100;"
        ),
        "115"
    );
}

#[test]
fn prototype_method_spread_expands_arguments() {
    assert_eq!(
        eval("let arr = [1]; let xs = [2, 3]; arr.push(...xs); arr.length;"),
        "3"
    );
}

#[test]
fn optional_method_spread_preserves_this_when_present() {
    assert_eq!(
        eval(
            "let obj = { base: 5, add(a, b) { return this.base + a + b; } }; \
             let xs = [2, 3]; \
             obj?.add(...xs);"
        ),
        "10"
    );
}

#[test]
fn optional_method_spread_short_circuits_nullish_receiver() {
    assert_eq!(
        eval("let obj = null; let xs = [1, 2]; obj?.add(...xs);"),
        "undefined"
    );
}
