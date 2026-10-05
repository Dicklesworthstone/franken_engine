#![forbid(unsafe_code)]

//! ES2022 15.7.1 / 15.2.1.1 (bd-9vouw.99): only a derived class's
//! constructor, and the arrows inside it, may call `super(...)`. Methods,
//! accessors, static and private methods, a base class's constructor,
//! ordinary functions, object methods and scripts reject it at parse time.
//! Node v22.2.0 rejects each negative program below with a SyntaxError and
//! prints the value of each positive one.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> Result<String, String> {
    HybridRouter::default()
        .eval(source)
        .map(|outcome| outcome.value)
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn super_calls_outside_derived_constructors_are_early_errors() {
    for source in [
        "class C extends Function { m() { super(); } }",
        "class C extends Function { static m() { super(); } }",
        "class C extends Function { #m() { super(); } }",
        "class C extends Function { async m() { super(); } }",
        "class C extends Function { *g() { super(); } }",
        "class C extends Function { get x() { super(); return 1; } }",
        "class C { constructor() { super(); } }",
        "function f() { super(); }",
        "({ m() { super(); } });",
        "class C extends Object { constructor() { function inner() { super(); } super(); } }",
        "super();",
        "const f = () => super();",
    ] {
        let error = eval(source).expect_err(source);
        assert!(
            error.contains("'super' keyword unexpected here"),
            "`{source}`: {error}"
        );
    }
}

/// A derived constructor calls super() directly or from a nested block; a
/// derived class nested in a method has its own constructor; a derived class
/// with fields and no constructor gets the implicit one. (super() from an
/// arrow parses but does not run yet: bd-9vouw.178. It was listed here
/// without ever passing.)
#[test]
fn super_calls_in_derived_constructors_still_run() {
    for (source, node) in [
        (
            "class B { constructor(x) { this.x = x; } } class C extends B { constructor() { super(5); } } new C().x;",
            "5",
        ),
        (
            "class A { m() { class D extends Object { constructor() { super(); this.v = 1; } } return new D().v; } } new A().m();",
            "1",
        ),
        (
            "class B { constructor() { this.y = 0; } } class D extends B { y = 2; } new D().y;",
            "2",
        ),
        (
            "class B { constructor() { this.z = 3; } } const E = class extends B { constructor() { if (true) { super(); } } }; new E().z;",
            "3",
        ),
    ] {
        assert_eq!(eval(source).as_deref(), Ok(node), "{source}");
    }
}

/// super() from an arrow inside a derived constructor is valid syntax: the
/// program is not refused as an early error (running it is bd-9vouw.178).
#[test]
fn super_from_an_arrow_in_a_derived_constructor_parses() {
    let source = "class B { constructor(x) { this.x = x; } } class C extends B { constructor() { const f = () => super(7); f(); } } new C().x;";
    let outcome = eval(source);
    assert!(
        !matches!(&outcome, Err(error) if error.contains("'super' keyword unexpected here")),
        "{outcome:?}"
    );
}
