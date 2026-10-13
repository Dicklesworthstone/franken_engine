//! bd-9vouw.396: two identifiers or numbers with no operator between them
//! (`a b`, `x = 1 2`) are a SyntaxError, so Function() throws a catchable
//! SyntaxError (also for `new Function({})`, whose body is
//! `[object Object]`); the engine refused them as unsupported syntax, which
//! aborted the program. Statements on separate lines are unaffected. The
//! line is Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn juxtaposed_operands_are_catchable_syntax_errors() {
    let source = r#"
var cases = ["a b", "x = 1 2", "return a b;", "var y = c d;"];
var r = cases.map(function (s) {
  try { Function(s); return "ok"; } catch (e) { return e.name; }
});
try { new Function({}); r.push("object-body:ok"); } catch (e) { r.push("object-body:" + e.name); }
var a = 1
var b = 2
r.push(a + b);
console.log(r.join(" "));
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
        ["SyntaxError SyntaxError SyntaxError SyntaxError object-body:SyntaxError 3",]
    );
}
