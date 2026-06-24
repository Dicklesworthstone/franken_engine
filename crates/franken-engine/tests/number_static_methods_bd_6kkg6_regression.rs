//! Regression for bd-6kkg6: `Number` STATIC methods unresolved via member
//! access. Before the fix `Number.isInteger(5)` faulted ("expected object, got
//! undefined") because the lowering pipeline never intercepted `Number.<static>`
//! member-calls — the `Number` global has no eval-scope binding, so the member
//! resolved to `undefined` and the call faulted. The execution handlers
//! (builtin:NumberIsInteger / NumberIsFinite / NumberIsNaN / NumberParseInt /
//! NumberParseFloat) already existed; only the lowering call-site interception
//! was missing (cf. the Math / Object / JSON global-static interceptions).
use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => o.value.to_string(),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn number_is_integer() {
    assert_eq!(eval("Number.isInteger(5);"), "true");
    assert_eq!(eval("Number.isInteger(5.5);"), "false");
    assert_eq!(eval("Number.isInteger(\"5\");"), "false"); // strict: no coercion
}

#[test]
fn number_is_finite() {
    assert_eq!(eval("Number.isFinite(7);"), "true");
    assert_eq!(eval("Number.isFinite(1.5);"), "true");
    assert_eq!(eval("Number.isFinite(\"7\");"), "false"); // strict: no coercion
}

#[test]
fn number_is_nan() {
    assert_eq!(eval("Number.isNaN(0/0);"), "true");
    assert_eq!(eval("Number.isNaN(5);"), "false");
    assert_eq!(eval("Number.isNaN(\"NaN\");"), "false"); // strict: no coercion
}

#[test]
fn number_parse_int_and_float() {
    assert_eq!(eval("Number.parseInt(\"42\");"), "42");
    assert_eq!(eval("Number.parseInt(\"FF\", 16);"), "255");
    assert_eq!(eval("Number.parseFloat(\"3.14\");"), "3.14");
}

#[test]
fn number_static_in_expression_context() {
    // Used as a sub-expression value, not just a statement.
    assert_eq!(eval("Number.isInteger(4) && Number.isInteger(6);"), "true");
    assert_eq!(
        eval("let xs = [1, 2.5, 3]; xs.filter(x => Number.isInteger(x)).length;"),
        "2"
    );
}

#[test]
fn number_binding_is_honored_not_shadowed() {
    // A user binding named `Number` must NOT be reinterpreted as the global.
    // Here `Number` is a plain object with its own `isInteger` returning a marker.
    assert_eq!(
        eval("let Number = { isInteger: (x) => 999 }; Number.isInteger(5);"),
        "999"
    );
}
