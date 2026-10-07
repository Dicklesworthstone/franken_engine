#![forbid(unsafe_code)]

//! `new String(symbol)` is ToString(symbol), a TypeError (ES2020 21.1.1.1 step
//! 2: only a call answers a Symbol's descriptive string); it boxed
//! "Symbol(s)". Calling String on a symbol, and String.prototype.valueOf /
//! toString on wrappers and primitives, keep their behavior (Test262
//! built-ins/String/symbol-wrapping.js).

use frankenengine_engine::HybridRouter;

/// Expected line is Node v22.2.0's output, captured programmatically from the
/// same source.
#[test]
fn new_string_of_a_symbol_is_a_type_error() {
    let source = r#"function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var sym = Symbol("s");
console.log(k(function () { return new String(sym); }), k(function () { return String(sym); }), k(function () { return String.prototype.valueOf.call({}); }), k(function () { return String.prototype.toString.call(new String("w")); }), k(function () { return String.prototype.valueOf.call("p"); }));
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["TypeError Symbol(s) TypeError w p",]);
}
