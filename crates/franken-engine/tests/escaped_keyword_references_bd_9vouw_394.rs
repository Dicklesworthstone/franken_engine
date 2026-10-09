//! bd-9vouw.394: a reserved word spelled with a unicode escape is still
//! reserved (ES2020 11.6.2): `await` in an async function, `yield`
//! in a generator or strict code and `if` anywhere are SyntaxErrors as
//! identifier references, while an escaped ordinary identifier still names
//! its binding. The engine accepted the four escaped keywords. Each case
//! compiles with Function(). The lines are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn escaped_reserved_words_are_not_identifier_references() {
    let source = r#"
var r = [];
function t(n, src) { try { Function(src); r.push(n + ":ok"); } catch (e) { r.push(n + "!" + e.name); } }
t("escaped-await-in-async", "return async function () { void \\u0061wait; }");
t("escaped-yield-in-generator", "return function* () { void yi\\u0065ld; }");
t("escaped-yield-strict", "'use strict'; void yi\\u0065ld;");
t("escaped-keyword", "void \\u0069f;");
t("escaped-plain-identifier", "var \\u0061bc = 1; return \\u0061bc;");
console.log(r.join(" | "));
var abc = 2;
console.log(abc, Function("var \\u0061bc = 3; return abc;")());
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
            "escaped-await-in-async!SyntaxError | escaped-yield-in-generator!SyntaxError | escaped-yield-strict!SyntaxError | escaped-keyword!SyntaxError | escaped-plain-identifier:ok",
            "2 3",
        ]
    );
}
