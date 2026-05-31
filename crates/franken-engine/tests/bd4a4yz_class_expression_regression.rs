//! bd-4a4yz regression: a class in EXPRESSION position must evaluate to a
//! constructor function, not fault with "expected function, got string".
//!
//! Root cause: the parser had no expression-position class arm, so it never
//! produced `Expression::ClassExpression`. `class {...}` fell through to a
//! string-yielding fallback, so `new (class{})()`, `let X = class{}; new X()`,
//! and even `typeof (class{})` all faulted at runtime. Fixed by adding
//! `parse_class_expression` (shares `parse_class_parts` with the declaration
//! form) and a dispatch arm in the primary-expression parser.

use frankenengine_engine::HybridRouter;

fn eval_ok(src: &str) -> String {
    let mut router = HybridRouter::default();
    match router.eval(src) {
        Ok(out) => out.value,
        Err(e) => panic!("expected Ok for {src:?}, got Err: {e:?}"),
    }
}

#[test]
fn typeof_class_expression_is_function() {
    // The whole point: evaluating a class expression must yield a function.
    assert_eq!(eval_ok("typeof (class { constructor(){} })"), "function");
}

#[test]
fn anonymous_class_expression_bound_then_constructed() {
    assert_eq!(
        eval_ok("let X = class { constructor(){ this.x = 3; } }; let c = new X(); c.x;"),
        "3"
    );
}

#[test]
fn named_class_expression_bound_then_constructed() {
    assert_eq!(
        eval_ok("let X = class C { constructor(){ this.x = 7; } }; let c = new X(); c.x;"),
        "7"
    );
}

#[test]
fn inline_new_class_expression() {
    // The original bd-4a4yz repro shape.
    assert_eq!(
        eval_ok("let c = new (class { constructor(){ this.x = 5; } })(); c.x;"),
        "5"
    );
}

/// bd-4a4yz fixes class-EXPRESSION *value* production (the parser now emits
/// `Expression::ClassExpression`). Calling a prototype METHOD on an instance is
/// a separate concern tracked by bd-62un6 ("class method dispatch faults"). This
/// non-asserting probe scopes whether that gap is expression-specific or also
/// affects class declarations, so bd-62un6 can be triaged accurately. It does
/// not gate the bd-4a4yz fix.
#[test]
fn method_dispatch_scope_probe_bd62un6() {
    for (label, src) in [
        (
            "decl-method",
            "class C { m(){ return 1; } } let c = new C(); c.m();",
        ),
        (
            "expr-method",
            "let X = class { m(){ return 1; } }; let c = new X(); c.m();",
        ),
        (
            "decl-field-then-method",
            "class C { constructor(){ this.v = 4; } get2(){ return this.v + this.v; } } \
             let c = new C(); c.get2();",
        ),
        (
            "expr-field-then-method",
            "let X = class { constructor(){ this.v = 4; } get2(){ return this.v + this.v; } }; \
             let c = new X(); c.get2();",
        ),
    ] {
        let mut router = HybridRouter::default();
        match router.eval(src) {
            Ok(o) => eprintln!("[{label}] OK value={}", o.value),
            Err(e) => eprintln!("[{label}] ERR {e}"),
        }
    }
}

#[test]
fn class_declaration_still_works() {
    // Guard against the shared-helper refactor regressing the statement form.
    assert_eq!(
        eval_ok("class C { constructor(){ this.x = 9; } } let c = new C(); c.x;"),
        "9"
    );
    assert_eq!(eval_ok("class C { constructor(){} } typeof C;"), "function");
}
