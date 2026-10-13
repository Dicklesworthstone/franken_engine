//! bd-9vouw.392: a label nested in a statement with the same label is an
//! early SyntaxError (ES2020 13.13.1: `L: { L: 0; }`, `A: A: 0;`), while
//! sibling labels, distinct labels and the same label inside an inner
//! function are fine. Duplicates were accepted. Each case compiles its
//! body with Function(), so a SyntaxError is caught. The line is Node
//! v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn nested_duplicate_labels_are_syntax_errors() {
    let source = r#"
var r = [];
function t(name, src) { try { Function(src); r.push(name + ":ok"); } catch (e) { r.push(name + "!" + e.constructor.name); } }
t("nested-block", "L: { L: 0; }");
t("nested-loop", "L: for (;;) { L: break L; }");
t("chained", "A: A: 0;");
t("siblings", "L: 0; L: 1;");
t("distinct", "A: B: 0;");
t("inner-function", "L: { (function () { L: 0; })(); }");
t("loop-break", "L: for (;;) { break L; }");
console.log(r.join(" | "));
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
            "nested-block!SyntaxError | nested-loop!SyntaxError | chained!SyntaxError | siblings:ok | distinct:ok | inner-function:ok | loop-break:ok",
        ]
    );
}
