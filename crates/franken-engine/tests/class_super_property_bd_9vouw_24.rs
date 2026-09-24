//! bd-9vouw.24: `super.x` / `super.m()` in class methods, accessors and
//! static methods.
//!
//! The parser rejected every `super` property reference in a class body
//! ("super expressions are not supported"); a non-call `super.x` ran getters
//! against the super prototype instead of `this`; and class accessors had no
//! [[HomeObject]]. Expected strings are what Node v22.2.0 prints for the same
//! programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn super_method_calls_in_instance_methods() {
    check(
        "class A { m() { return 1; } } class B extends A { m() { return super.m() + 1; } } new B().m();",
        "2",
    );
    check(
        "class A { m() { return 'a'; } } class B extends A { m() { return super['m']() + 'b'; } } new B().m();",
        "ab",
    );
    // Each level's [[HomeObject]] picks the next prototype up the chain.
    check(
        "class A { constructor(x) { this.x = x; } describe() { return 'A' + this.x; } } \
         class B extends A { describe() { return super.describe() + '>B'; } } \
         class C extends B { describe() { return super.describe() + '>C'; } } \
         new C(7).describe();",
        "A7>B>C",
    );
}

#[test]
fn super_property_reads_run_getters_with_this() {
    check(
        "class A { constructor() { this.n = 1; } get d() { return this.n * 2; } } \
         class B extends A { constructor() { super(); this.n += 1; } } \
         class C extends B { get d() { return super.d + 10; } } \
         new C().d;",
        "14",
    );
}

#[test]
fn super_in_static_methods_resolves_against_the_parent_constructor() {
    check(
        "class A { static s() { return 's'; } } class B extends A { static s() { return super.s() + '2'; } } B.s();",
        "s2",
    );
}

#[test]
fn derived_classes_inherit_static_members() {
    check(
        "class A { static s() { return 1; } } class B extends A {} B.s();",
        "1",
    );
    // `this` is the derived constructor; own `name` is never inherited.
    check(
        "class A { static who() { return this.name; } } class B extends A {} \
         B.who() + ':' + B.name + ':' + A.name;",
        "B:B:A",
    );
}

#[test]
fn class_accessors_carry_their_spec_name() {
    check(
        "class A { get g() { return 1; } } class B extends A { get g() { return super.g + 1; } } \
         Object.getOwnPropertyDescriptor(B.prototype, 'g').get.name;",
        "get g",
    );
}

#[test]
fn object_literal_super_still_works() {
    check(
        "const p = { m() { return 'p'; } }; const o = { m() { return super.m() + 'c'; } }; \
         Object.setPrototypeOf(o, p); o.m();",
        "pc",
    );
}
