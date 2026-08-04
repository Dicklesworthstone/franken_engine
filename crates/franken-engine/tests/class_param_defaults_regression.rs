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
fn class_expr_constructor_default_param_missing_arg_uses_default() {
    assert_eq!(
        eval_value("let c = new (class { constructor(x = 5) { this.x = x; } })(); c.x;"),
        "5"
    );
}

#[test]
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
fn class_stmt_method_default_param_missing_arg_uses_default() {
    assert_eq!(
        eval_value("class C { m(x = 7) { return x; } } let c = new C(); c.m();"),
        "7"
    );
}

#[test]
fn class_stmt_method_default_param_supplied_arg_wins() {
    assert_eq!(
        eval_value("class C { m(x = 7) { return x; } } let c = new C(); c.m(4);"),
        "4"
    );
}

// ---- class-expression method ----------------------------------------------

#[test]
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
fn diag_plain_class_stmt_method() {
    assert_eq!(
        eval_value("class C { m() { return 7; } } let c = new C(); c.m();"),
        "7"
    );
}

#[test]
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

#[test]
fn class_parameter_defaults_capture_outer_binding_before_body_shadow_bd_4thqe() {
    let cases = [
        (
            "class statement constructor",
            "const x = 42; class C { constructor(a = x) { let x = 7; this.v = a; } } new C().v;",
        ),
        (
            "class statement method",
            "const x = 42; class C { m(a = x) { let x = 7; return a; } } new C().m();",
        ),
        (
            "class expression constructor",
            "const x = 42; let C = class { constructor(a = x) { let x = 7; this.v = a; } }; new C().v;",
        ),
        (
            "class expression method",
            "const x = 42; let C = class { m(a = x) { let x = 7; return a; } }; new C().m();",
        ),
    ];

    for (form, source) in cases {
        assert_eq!(eval_value(source), "42", "{form}");
    }
}

#[test]
fn class_parameter_defaults_honor_outer_static_global_shadows_bd_4thqe() {
    let cases = [
        "const Math = { abs: n => n + 40 }; class C { constructor(v = Math.abs(2)) { this.v = v; } } new C().v;",
        "const Math = { abs: n => n + 40 }; class C { m(v = Math.abs(2)) { return v; } } new C().m();",
        "const Math = { abs: n => n + 40 }; let C = class { constructor(v = Math.abs(2)) { this.v = v; } }; new C().v;",
        "const Math = { abs: n => n + 40 }; let C = class { m(v = Math.abs(2)) { return v; } }; new C().m();",
    ];

    for source in cases {
        assert_eq!(eval_value(source), "42");
    }
}

#[test]
fn named_class_expression_self_is_visible_to_its_defaults_bd_4thqe() {
    assert_eq!(
        eval_value(
            "let Inner = 7;\
             let C = class Inner {\
                 constructor(v = Inner) { let Inner = 9; this.v = v; }\
                 m(v = Inner) { let Inner = 9; return v; }\
             };\
             let D = C; C = 0; let d = new D();\
             d.v === D && d.m() === D && Inner === 7;"
        ),
        "true"
    );
}
