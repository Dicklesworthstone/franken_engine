//! bd-9vouw.398: a yield expression as a binary operand or a `?:`
//! condition, a line break between `yield` and `*` or before `=>`, and a
//! private name as a destructuring key are catchable SyntaxErrors through
//! Function(); valid look-alikes run. Expected lines are Node v22.2.0's
//! output.

use frankenengine_engine::HybridRouter;

#[test]
fn yield_and_arrow_early_errors_are_syntax_errors() {
    let source = r#"
var out = [];
function t(name, src) {
  try { Function(src); out.push(name + ":ok"); } catch (e) { out.push(name + "!" + e.name); }
}
t("fn-weak", "function* g() { yield 3 + yield 4; }");
t("fn-logical", "function* g() { yield || yield; }");
t("fn-cond", "function* g() { yield ? yield : yield; }");
t("method-weak", "var o = { *g() { yield 3 + yield 4; } };");
t("method-cond", "var o = { *g() { yield ? yield : yield; } };");
t("arrow-newline", "var f = ()\n=> 1;");
t("arrow-ident-newline", "var f = x\n=> 1;");
t("private-destructure", "class C { #x = 1; m() { const { #x: x } = this; } }");
console.log(out.join(" | "));
var ok = [];
function v(name, src) {
  try { ok.push(name + "=" + Function(src)()); } catch (e) { ok.push(name + "!" + e.name); }
}
v("paren-yield-operand", "function* g() { var a = 3 + (yield 4); return a; } var it = g(); it.next(); return it.next(5).value;");
v("yield-operand-of-paren", "function* g() { return (yield) ? 'y' : 'n'; } var it = g(); it.next(); return it.next(1).value;");
v("yield-star", "function* g() { yield* [1, 2]; } return [...g()].join(',');");
v("yield-plus-expression", "function* g() { yield 3 + 4; } return g().next().value;");
v("conditional-operand", "function* g() { var r = 1 ? yield 2 : yield 3; return r; } return g().next().value;");
v("arrow-body-newline", "var f = x =>\n x + 1; return f(1);");
v("arrow-params-newline", "var f = (a,\n b) => a + b; return f(1, 2);");
v("private-member-value", "class C { #x = 7; m() { const { x } = { x: this.#x }; return x; } } return new C().m();");
console.log(ok.join(" | "));
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
            "fn-weak!SyntaxError | fn-logical!SyntaxError | fn-cond!SyntaxError | method-weak!SyntaxError | method-cond!SyntaxError | arrow-newline!SyntaxError | arrow-ident-newline!SyntaxError | private-destructure!SyntaxError",
            "paren-yield-operand=8 | yield-operand-of-paren=y | yield-star=1,2 | yield-plus-expression=7 | conditional-operand=2 | arrow-body-newline=2 | arrow-params-newline=3 | private-member-value=7",
        ]
    );
}
