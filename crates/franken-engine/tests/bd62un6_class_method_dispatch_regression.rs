//! bd-62un6 regression: calling a prototype method on a class instance must
//! work, for both class declarations and class expressions.
//!
//! Root cause: class definition attaches instance methods with
//! `LoadBinding{C}; GetProperty{"prototype"}; CreateFunction{m}; SetProperty{"m"}`.
//! The interpreter's GetProperty handler had no arm for function/closure
//! receivers, so reading `C.prototype` (C being the constructor closure) hit
//! the fallback and faulted "type error: expected object, got function" — at
//! class-DEFINITION time, before `new`/dispatch. So any class with a
//! non-constructor method faulted (decl and expr alike); constructor-only
//! classes never hit it. Fixed by routing `fn.prototype` to the same lazily
//! created object that `Construct` links instances to
//! (ensure_function_prototype), so methods land where instances look them up.

use frankenengine_engine::HybridRouter;

fn eval_ok(src: &str) -> String {
    let mut router = HybridRouter::default();
    match router.eval(src) {
        Ok(out) => out.value,
        Err(e) => panic!("expected Ok for {src:?}, got Err: {e:?}"),
    }
}

#[test]
fn declaration_method_dispatch() {
    assert_eq!(
        eval_ok("class C { m(){ return 1; } } let c = new C(); c.m();"),
        "1"
    );
}

#[test]
fn expression_method_dispatch() {
    assert_eq!(
        eval_ok("let X = class { m(){ return 1; } }; let c = new X(); c.m();"),
        "1"
    );
}

#[test]
fn declaration_field_then_method() {
    assert_eq!(
        eval_ok(
            "class C { constructor(){ this.v = 4; } get2(){ return this.v + this.v; } } \
             let c = new C(); c.get2();"
        ),
        "8"
    );
}

#[test]
fn expression_field_then_method() {
    assert_eq!(
        eval_ok(
            "let X = class { constructor(){ this.v = 4; } get2(){ return this.v + this.v; } }; \
             let c = new X(); c.get2();"
        ),
        "8"
    );
}

#[test]
fn method_uses_this_and_args() {
    assert_eq!(
        eval_ok(
            "class C { constructor(){ this.base = 10; } add(n){ return this.base + n; } } \
             let c = new C(); c.add(5);"
        ),
        "15"
    );
}

#[test]
fn multiple_methods_one_class() {
    assert_eq!(
        eval_ok(
            "class C { a(){ return 1; } b(){ return 2; } } \
             let c = new C(); c.a() + c.b();"
        ),
        "3"
    );
}

#[test]
fn field_access_still_works() {
    // Guard: the constructor-only / field path that already worked must not regress.
    assert_eq!(
        eval_ok("class C { constructor(){ this.x = 3; } } let c = new C(); c.x;"),
        "3"
    );
}
