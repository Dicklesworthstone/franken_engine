//! bd-9vouw.345: a function's own `prototype` is never enumerable (ES2020
//! 9.2.10 MakeConstructor; the built-in constructors' `prototype` is
//! non-writable, non-enumerable and non-configurable), and
//! Object.prototype.propertyIsEnumerable now says so, as
//! getOwnPropertyDescriptor already did: it answered true for the built-in
//! constructors and for user functions and classes. A function's `name`,
//! the built-ins' own enumerable keys and an ordinary object's `prototype`
//! data property are checked alongside. Node v22.2.0 gives this line.

use frankenengine_engine::HybridRouter;

#[test]
fn function_prototype_properties_are_not_enumerable() {
    let source = r#"
function f() {}
class C {}
var out = [Function, Object, String, Boolean, Error, RegExp, Array, Number, f, C, Map, Promise].map(function (g) { return g.propertyIsEnumerable('prototype'); });
out.push(f.propertyIsEnumerable('name'), Object.keys(String).length, f.hasOwnProperty('prototype'));
var o = { prototype: 1 };
out.push(o.propertyIsEnumerable('prototype'));
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "false false false false false false false false false false false false false 0 true true"
        ]
    );
}
