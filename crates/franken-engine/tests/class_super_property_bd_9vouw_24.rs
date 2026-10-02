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

/// `super.m(...xs)` spreads its arguments. CallMethod took a fixed argument
/// count and the spread evaluated to its array, so the parent received the
/// array as one argument: espree's parser subclass forwards
/// `finishNode(...args)` to `super.finishNode(...args)`, and `espree.parse`
/// threw "expected object, got undefined". Instance, computed, static and
/// object-literal super calls; `this` stays the caller's.
#[test]
fn super_method_calls_spread_their_arguments() {
    check(
        "class A { f(...a) { return a.join(\",\"); } static s(a, b) { return a + b; } }\n\
         class B extends A { g(...x) { return super.f(...x); } h(x) { return super.f(0, ...x, 9); } \
         c(x) { return super[\"f\"](...x); } static t(...x) { return super.s(...x); } }\n\
         var base = { f(a, b) { return a + \"/\" + b + \"/\" + this.tag; } };\n\
         var o = { __proto__: base, tag: \"t\", g(...x) { return super.f(...x); } };\n\
         class P { finishNode(n, t) { n.type = t; return n; } }\n\
         class E extends P { finishNode(...args) { const r = super.finishNode(...args); r.z = 1; return r; } }\n\
         [new B().g(1, 2, 3), new B().h([1, 2]), new B().c([4, 5]), B.t(1, 2), o.g(\"a\", \"b\"), \
         JSON.stringify(new E().finishNode({}, \"Program\"))].join(\" \");",
        "1,2,3 0,1,2,9 4,5 3 a/b/t {\"type\":\"Program\",\"z\":1}",
    );
}

/// bd-9vouw.143: `super` in a generator method. Generator methods had no
/// [[HomeObject]] and the generator's frame no super binding, so
/// `*g() { yield super.v(); }` threw "expected object, got undefined"; a Set
/// subclass's `*[Symbol.iterator]() { ... super.values() ... }` failed once
/// bd-9vouw.141 made for-of call it. Class and object-literal generator
/// methods, computed keys and `yield*` over a super call; the method keeps
/// its name. No-claim: async generator methods take the same path but are
/// not covered here.
#[test]
fn super_in_generator_methods() {
    check(
        "class A { v() { return 1; } }\n\
         class B extends A { *g() { yield super.v(); } *[\"c\"]() { yield super.v() + 1; } }\n\
         class S extends Set { *g() { yield* super.values(); } }\n\
         var o = { __proto__: { w() { return 3; } }, *g() { yield super.w(); } };\n\
         [[...new B().g()].join(), [...new B().c()].join(), [...new S([4, 5]).g()].join(), \
         [...o.g()].join(), new B().g.name].join(\" \");",
        "1 2 4,5 3 g",
    );
}
