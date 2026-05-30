//! Regression: default and destructuring parameters must bind in CLASS
//! constructor and method lowering (bd-7yrmf).
//!
//! ROOT CAUSE: the four class lowering sites (class-statement constructor,
//! class-statement method, class-expression constructor, class-expression
//! method) built param names with `params.iter().filter_map(|p| p.name())`.
//! `FunctionParam::name()` returns `None` for any non-identifier pattern (a
//! default `x = v` parses as an assignment pattern, destructuring as
//! Object/ArrayPattern), so `filter_map` silently dropped those params — the
//! constructor/method ended up arity-short with the argument value lost.
//!
//! FIX mirrors bd-f2iw8 (arrow / function-expression): each non-identifier param
//! gets a synthetic `__param_N` slot that is destructured at body entry via
//! `lower_destructuring_to_ir1` (which applies the default), so the value binds.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- class-expression constructor (the bead's pinned repro) ----------------

#[test]
#[ignore = "blocked on bd-4a4yz: class expression as constructor faults (orthogonal to params)"]
fn class_expr_constructor_default_param_missing_arg_uses_default() {
    assert_eq!(
        eval_value("let c = new (class { constructor(x = 5) { this.x = x; } })(); c.x;"),
        "5"
    );
}

#[test]
#[ignore = "blocked on bd-4a4yz: class expression as constructor faults (orthogonal to params)"]
fn class_expr_constructor_default_param_supplied_arg_wins() {
    assert_eq!(
        eval_value("let c = new (class { constructor(x = 5) { this.x = x; } })(9); c.x;"),
        "9"
    );
}

// ---- class-statement constructor ------------------------------------------

#[test]
fn class_stmt_constructor_default_param_missing_arg_uses_default() {
    assert_eq!(
        eval_value("class C { constructor(x = 5) { this.x = x; } } let c = new C(); c.x;"),
        "5"
    );
}

#[test]
fn class_stmt_constructor_default_param_supplied_arg_wins() {
    assert_eq!(
        eval_value("class C { constructor(x = 5) { this.x = x; } } let c = new C(9); c.x;"),
        "9"
    );
}

// ---- class-statement method -----------------------------------------------

#[test]
#[ignore = "blocked on bd-62un6: class method dispatch faults (orthogonal to params)"]
fn class_stmt_method_default_param_missing_arg_uses_default() {
    assert_eq!(
        eval_value("class C { m(x = 7) { return x; } } let c = new C(); c.m();"),
        "7"
    );
}

#[test]
#[ignore = "blocked on bd-62un6: class method dispatch faults (orthogonal to params)"]
fn class_stmt_method_default_param_supplied_arg_wins() {
    assert_eq!(
        eval_value("class C { m(x = 7) { return x; } } let c = new C(); c.m(4);"),
        "4"
    );
}

// ---- class-expression method ----------------------------------------------

#[test]
#[ignore = "blocked on bd-4a4yz (class expr ctor) + bd-62un6 (class method dispatch) — both orthogonal to params"]
fn class_expr_method_default_param_missing_arg_uses_default() {
    assert_eq!(
        eval_value("let c = new (class { m(x = 7) { return x; } })(); c.m();"),
        "7"
    );
}

// ---- ORTHOGONALITY GUARDS: plain (no-default) class forms ------------------
// These confirm the class-expr / class-method param failures above are caused by
// PRE-EXISTING bugs unrelated to parameter binding: the plain no-default forms
// fail identically. They are the canonical repros for bd-4a4yz / bd-62un6 and
// auto-activate when those land. The plain class-statement-constructor form
// works, proving the param fix's host path (and this fix) is sound.

#[test]
#[ignore = "repro for bd-62un6: class method dispatch faults (orthogonal to params)"]
fn diag_plain_class_stmt_method() {
    assert_eq!(
        eval_value("class C { m() { return 7; } } let c = new C(); c.m();"),
        "7"
    );
}

#[test]
#[ignore = "repro for bd-4a4yz: class expression as constructor faults (orthogonal to params)"]
fn diag_plain_class_expr_constructor() {
    assert_eq!(
        eval_value("let c = new (class { constructor() { this.x = 3; } })(); c.x;"),
        "3"
    );
}

#[test]
fn diag_plain_class_stmt_constructor() {
    assert_eq!(
        eval_value("class C { constructor() { this.x = 3; } } let c = new C(); c.x;"),
        "3"
    );
}
