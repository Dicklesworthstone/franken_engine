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
    assert_eq!(
        eval("let o = Object.assign({}, {a:1}, {b:2}); o.a + o.b;"),
        "3"
    );
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
    assert_eq!(
        eval("let o = {a:1}; Object.freeze(o); Object.isFrozen(o);"),
        "true"
    );
    assert_eq!(eval("Object.isFrozen({});"), "false");
}

#[test]
fn object_create_and_keys() {
    // Object.create(null) yields an object with no inherited keys.
    assert_eq!(
        eval("Object.keys(Object.assign(Object.create(null), {a:1,b:2})).length;"),
        "2"
    );
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
fn string_from_code_point_invalid_values_throw_range_error_bd_xulus() {
    assert_eq!(eval("String.fromCodePoint(65, 66);"), "AB");

    for source in [
        "String.fromCodePoint(65, 0x110000);",
        "String.fromCodePoint(-1);",
        "String.fromCodePoint(1.5);",
        "String.fromCodePoint(undefined);",
    ] {
        let out = eval(source);
        assert!(
            out.contains("range error") && out.contains("String.fromCodePoint"),
            "{source} should throw RangeError instead of returning a partial string, got {out:?}"
        );
    }
}

#[test]
fn math_and_string_builtins_use_modular_float_coercion() {
    // ECMA `Math.imul`/`Math.clz32`/`String.fromCharCode` apply modular
    // ToInt32/ToUint32/ToUint16 to their operands. Rust's `f64 as i32`/`as u32`
    // *saturates*, so before the fix any float operand outside the 32-bit range
    // clamped instead of wrapping. These cases all exercise the float branch.

    // Math.imul: ToUint32(2**31)=2147483648 -> int32 -2147483648; *2 wraps to 0
    // (saturating gave i32::MAX*2 wrapping = -2).
    assert_eq!(eval("Math.imul(2147483648.5, 2);"), "0");

    // Math.clz32: ToUint32(2**32)=0 -> clz32(0)=32 (saturating gave clz32(MAX)=0).
    assert_eq!(eval("Math.clz32(4294967296.5);"), "32");
    // Math.clz32(-1.5): ToUint32=0xFFFFFFFF -> clz32=0 (saturating gave 0->32).
    assert_eq!(eval("Math.clz32(-1.5);"), "0");

    // String.fromCharCode: ToUint16(-1.5)=0xFFFF (saturating gave 0x0000).
    assert_eq!(eval("String.fromCharCode(-1.5).charCodeAt(0);"), "65535");
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
    assert_eq!(eval("Array.isArray([1]) && Object.is(2, 2);"), "true");
}
