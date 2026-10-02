//! bd-9vouw.93: Object.prototype.toString reads @@toStringTag with [[Get]]
//! (ES2020 19.1.3.6 step 15), so a getter supplies the tag: a class's
//! `get [Symbol.toStringTag]()`, an object literal's, one defined with
//! Object.defineProperty, one inherited, and one on a subclass of a builtin
//! (which shadows the builtin prototype's tag). Only data properties were
//! read; a getter left "[object Object]", or the builtin kind's name.
//! Expected strings are Node v22.2.0's output for the same programs.
//!
//! No-claim: a Proxy's get trap is not consulted for @@toStringTag here;
//! implicit string conversions (`String(obj)`, template literals, `+`) keep
//! the data-property lookup, so `String(new P())` is still "[object Object]".

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// Getters in classes, literals, defineProperty and the prototype chain.
#[test]
fn to_string_tag_getter_getter_shapes() {
    let source = "var T = Object.prototype.toString;\n\
         class P { get [Symbol.toStringTag]() { return 'P'; } }\n\
         var proto = { get [Symbol.toStringTag]() { return 'Inh'; } };\n\
         [T.call({ [Symbol.toStringTag]: 'Data' }), T.call(new P()), T.call(Object.create(proto)),\n\
          T.call({ get [Symbol.toStringTag]() { return 'G'; } }),\n\
          T.call(Object.defineProperty({}, Symbol.toStringTag, { get() { return 'DP'; } }))].join(' ');";
    assert_eq!(
        eval(source),
        "[object Data] [object P] [object Inh] [object G] [object DP]"
    );
}

/// A subclass's getter shadows the builtin prototype's tag; without one the builtin tag stays.
#[test]
fn to_string_tag_getter_getter_on_builtin_subclasses() {
    let source = "var T = Object.prototype.toString;\n\
         class M3 extends Map {}\n\
         class M4 extends Map { get [Symbol.toStringTag]() { return 'M4'; } }\n\
         class D extends Date { get [Symbol.toStringTag]() { return 'D'; } }\n\
         class A extends Array { get [Symbol.toStringTag]() { return 'A'; } }\n\
         [T.call(new M3()), T.call(new M4()), T.call(new D(0)), T.call(new A()), T.call(new (class extends Set {})())].join(' ');";
    assert_eq!(
        eval(source),
        "[object Map] [object M4] [object D] [object A] [object Set]"
    );
}

/// A getter returning a non-string keeps the builtinTag, and the getter sees the object as `this`.
#[test]
fn to_string_tag_getter_non_string_and_receiver() {
    let source = "var T = Object.prototype.toString, seen;\n\
         var o = { get [Symbol.toStringTag]() { seen = this; return 42; } };\n\
         class Q extends Array { get [Symbol.toStringTag]() { return undefined; } }\n\
         [T.call(o), seen === o, T.call(new Q()), T.call(Object.defineProperty(new Date(0), Symbol.toStringTag, { get() { return null; } }))].join(' ');";
    assert_eq!(
        eval(source),
        "[object Object] true [object Array] [object Date]"
    );
}
