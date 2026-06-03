//! bd-ppfds regression: class `extends` must inherit prototype methods.
//!
//! Root cause: the extends lowering wires `Child.prototype.__proto__ =
//! Parent.prototype` via a string-keyed SetProperty, but the interpreter stored
//! `__proto__` as a data property instead of setting the internal
//! HeapObject.prototype link — so the prototype-chain walk never reached the
//! parent and inherited methods faulted ("expected function, got undefined").
//! Fixed by special-casing `__proto__` in GetProperty/SetProperty to read/set
//! the internal prototype link.

use frankenengine_engine::HybridRouter;

fn eval_ok(src: &str) -> String {
    let mut r = HybridRouter::default();
    match r.eval(src) {
        Ok(o) => o.value,
        Err(e) => panic!("expected Ok for {src:?}, got Err: {e:?}"),
    }
}

#[test]
fn inherited_method_dispatch() {
    assert_eq!(
        eval_ok("class A{ m(){ return 1; } } class B extends A{} let b=new B(); b.m();"),
        "1"
    );
}

#[test]
fn multi_level_inheritance() {
    assert_eq!(
        eval_ok("class A{ m(){ return 1; } } class B extends A{} class C extends B{} new C().m();"),
        "1"
    );
}

#[test]
fn override_shadows_parent() {
    assert_eq!(
        eval_ok("class A{ m(){ return 1; } } class B extends A{ m(){ return 2; } } new B().m();"),
        "2"
    );
}

#[test]
fn own_and_inherited_methods() {
    assert_eq!(
        eval_ok(
            "class A{ a(){ return 1; } } class B extends A{ b(){ return 2; } } \
             let o=new B(); o.a() + o.b();"
        ),
        "3"
    );
}

#[test]
fn proto_set_then_chain_read() {
    // Direct __proto__ assignment establishes the prototype link for lookups.
    assert_eq!(eval_ok("let p={v:9}; let o={}; o.__proto__=p; o.v;"), "9");
}

#[test]
fn proto_get_returns_internal_prototype() {
    // o.__proto__ reads back the object set via __proto__ (not undefined).
    assert_eq!(
        eval_ok("let p={}; let o={}; o.__proto__=p; typeof o.__proto__;"),
        "object"
    );
}

/// Diagnostic (non-asserting): isolate whether the gap is multi-level chain
/// walk (baseline, fixable) or the class `extends` __proto__ wiring (lowering).
#[test]
fn diag_proto_levels() {
    let mut r = HybridRouter::default();
    for (l, s) in [
        (
            "1level-plain-data",
            "let p={v:9}; let o={}; o.__proto__=p; o.v;",
        ),
        (
            "2level-plain-data",
            "let gp={v:9}; let p={}; p.__proto__=gp; let o={}; o.__proto__=p; o.v;",
        ),
        (
            "1level-plain-method",
            "let proto={m(){return 7;}}; let o={}; o.__proto__=proto; o.m();",
        ),
        (
            "extends-no-method",
            "class A{m(){return 1;}} class B extends A{} new B().m();",
        ),
    ] {
        match r.eval(s) {
            Ok(o) => eprintln!("[{l}] OK {}", o.value),
            Err(e) => eprintln!("[{l}] ERR {e}"),
        }
    }
}

#[test]
fn non_inherited_still_undefined() {
    // A method not present anywhere on the chain reads undefined (no false hit).
    assert_eq!(
        eval_ok("class A{ m(){ return 1; } } class B extends A{} typeof (new B().nope);"),
        "undefined"
    );
}
