#![forbid(unsafe_code)]

//! `super` property references inside object literal getters and setters
//! (ES2020 14.3.8: an accessor is a MethodDefinition, so HasSuperProperty is
//! allowed): the parser refused the whole program with "super expressions are
//! not supported" (Test262 language/expressions/object/getter-super-prop.js,
//! setter-super-prop.js). Class accessors already worked; this source covers
//! both.

use frankenengine_engine::HybridRouter;

/// Expected lines are Node v22.2.0's output, captured programmatically from the
/// same source.
#[test]
fn super_in_object_literal_accessors() {
    let source = r#"var proto = { x: 1, y: 2 };
var o = { __proto__: proto, get x() { return super.x + 10; }, set y(v) { super.y = v * 2; }, m() { return super.x; } };
console.log(o.x, o.m());
o.y = 5; console.log(o.y, proto.y);
class A { get g() { return 1; } }
class B extends A { get g() { return super.g + 1; } static get s() { return typeof super.constructor; } }
console.log(new B().g, B.s);
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["11 1", "undefined 2", "2 function",]);
}
