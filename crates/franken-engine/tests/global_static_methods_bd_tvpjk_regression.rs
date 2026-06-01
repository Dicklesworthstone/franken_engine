//! Regression for bd-tvpjk: Object/Array/String STATIC methods unresolved via
//! member access. Their execution handlers + id-registry entries already existed
//! in dispatch_builtin_hostcall_inner, but the lowering interception only wired
//! Object.keys/values/entries + JSON.parse/stringify — so Object.assign,
//! Array.isArray, String.fromCharCode, etc. faulted ("expected function/object,
//! got undefined") because the bare `Object`/`Array`/`String` globals have no
//! eval-scope binding. Fix extends the static-member interception (cf. bd-6kkg6).
use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => format!("{}", o.value),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn object_assign() {
    assert_eq!(eval("let o = Object.assign({}, {a:1}, {b:2}); o.a + o.b;"), "3");
    assert_eq!(eval("Object.assign({x:1}, {x:9}).x;"), "9"); // later sources win
}

#[test]
fn object_is() {
    // Object.is uses the receiver-placeholder calling convention — these caught
    // a real wiring bug (slot-0 routing returned "false" for Object.is(1,1)).
    assert_eq!(eval("Object.is(1, 1);"), "true");
    assert_eq!(eval("Object.is(1, 2);"), "false");
    assert_eq!(eval("Object.is(\"x\", \"x\");"), "true");
}

#[test]
fn object_is_extensible() {
    // Receiver-placeholder convention. This validates the WIRING: a fresh object
    // literal is extensible. (Note: the engine's Object.freeze does not yet mark
    // the object non-extensible, so `isExtensible` of a frozen object still
    // reports true — that is a separate handler-semantics gap, not a wiring bug;
    // tracked under bd-tvpjk's comments.)
    assert_eq!(eval("Object.isExtensible({});"), "true");
}

#[test]
fn object_get_own_property_names() {
    // Another slot-0 static, confirming the wiring delivers the receiver object
    // at slot 0.
    assert_eq!(eval("Object.getOwnPropertyNames({a:1,b:2}).length;"), "2");
}

#[test]
fn object_freeze_and_is_frozen() {
    assert_eq!(eval("let o = {a:1}; Object.freeze(o); Object.isFrozen(o);"), "true");
    assert_eq!(eval("Object.isFrozen({});"), "false");
}

#[test]
fn object_create_and_keys() {
    // Object.create(null) yields an object with no inherited keys.
    assert_eq!(eval("Object.keys(Object.assign(Object.create(null), {a:1,b:2})).length;"), "2");
}

#[test]
fn array_is_array() {
    assert_eq!(eval("Array.isArray([1,2,3]);"), "true");
    assert_eq!(eval("Array.isArray({});"), "false");
    assert_eq!(eval("Array.isArray(5);"), "false");
}

#[test]
fn array_from() {
    assert_eq!(eval("Array.from([1,2,3]).length;"), "3");
    assert_eq!(eval("Array.from([1,2,3], x => x * 2)[2];"), "6");
}

#[test]
fn string_from_char_code() {
    assert_eq!(eval("String.fromCharCode(65);"), "A");
    assert_eq!(eval("String.fromCharCode(72, 105);"), "Hi");
}

#[test]
fn static_globals_are_shadowable() {
    // A user binding named `Object` must NOT be reinterpreted as the global.
    assert_eq!(
        eval("let Object = { assign: () => 42 }; Object.assign({}, {});"),
        "42"
    );
}

#[test]
fn statics_compose_in_expressions() {
    assert_eq!(
        eval("Array.isArray([1]) && Object.is(2, 2);"),
        "true"
    );
}
