//! bd-9vouw.64 fields step 3: ES2022 15.7.1 early errors for class field
//! initializers. An initializer may not refer to `arguments` or call
//! `super(...)`, looking through arrow functions (which have neither of their
//! own) but not into ordinary functions, methods or class bodies. Node v22.2.0
//! rejects each negative program below with a SyntaxError and prints the
//! values of the positive ones.
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
fn arguments_and_super_calls_in_field_initializers_are_early_errors() {
    for source in [
        "class C { x = arguments; }",
        "class C { static x = () => arguments; }",
        "class C { x = () => { var t = () => arguments; }; }",
        "class C { x = typeof arguments; }",
        "class C { [1] = false ? {} : arguments; }",
        "class C { x = (a = arguments) => a; }",
        "class B {} class C extends B { x = super(); }",
        "class B {} class C extends B { x = () => super(); }",
        "class C { x = class extends (arguments, Object) {}; }",
    ] {
        let error = eval(source).expect_err(source);
        assert!(
            error.contains("a class field initializer may not contain"),
            "`{source}`: {error}"
        );
    }
}

/// Property names are not references, and ordinary functions, methods and
/// nested class members bind their own `arguments`; `super.x` is allowed.
#[test]
fn legal_neighbours_still_run() {
    for (source, node) in [
        (
            "const o = { arguments: 7 }; class C { x = o.arguments; y = { arguments: 1 }.arguments; }
             const c = new C(); [c.x, c.y].join(' ');",
            "7 1",
        ),
        (
            "class C { f = function () { return arguments.length; }; m = { g() { return arguments.length; } }; }
             const c = new C(); [c.f(1, 2), c.m.g(1, 2, 3)].join(' ');",
            "2 3",
        ),
        (
            "class B { get v() { return 5; } } class C extends B { x = super.v + 1; } new C().x;",
            "6",
        ),
        (
            "class C { k = class { m() { return arguments.length; } }; } new (new C().k)().m(1, 2);",
            "2",
        ),
    ] {
        assert_eq!(eval(source).as_deref(), Ok(node), "{source}");
    }
}
