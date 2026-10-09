//! bd-9vouw.397: class bodies with a second constructor, an escaped `#` or
//! a non-identifier escape in an element or member name, or two elements
//! on one line are catchable SyntaxErrors through Function(); valid
//! look-alikes still run. Expected lines are Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn class_element_early_errors_are_syntax_errors() {
    let source = r#"
var out = [];
function t(name, src) {
  try { Function(src); out.push(name + ":ok"); } catch (e) { out.push(name + "!" + e.name); }
}
t("duplicate-constructor", "class C { constructor() {} constructor() {} }");
t("escaped-hash-field", "class C { \\u0023field; }");
t("escaped-hash-method", "class C { \\u0023m() {} }");
t("escaped-hash-member", "class C { #f; m() { return this.\\u0023f; } }");
t("joiner-private-start", "class C { #\\u200D_x; }");
t("nul-field", "class C { \\u0000; }");
t("same-line-elements", "class C { field method() {} }");
console.log(out.join(" | "));
var ok = [];
function v(name, src) {
  try { ok.push(name + "=" + Function(src)()); } catch (e) { ok.push(name + "!" + e.name); }
}
v("static-constructor", "class C { constructor() {} static constructor() { return 5; } } return C.constructor();");
v("escaped-field", "class C { \\u0061bc = 1; } return new C().abc;");
v("escaped-private", "class C { #\\u0061 = 2; get() { return this.#a; } } return new C().get();");
v("escaped-member", "var o = { b: 4 }; return o.\\u0062;");
v("joiner-continues", "class C { #a\\u200D = 6; get() { return this.#a\\u200D; } } return new C().get();");
v("asi-elements", "class C { x\n y() { return 3; } } return new C().y();");
v("async-newline-field", "class C { async\n m() { return 7; } } var c = new C(); return ('async' in c) + ',' + c.m();");
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
            "duplicate-constructor!SyntaxError | escaped-hash-field!SyntaxError | escaped-hash-method!SyntaxError | escaped-hash-member!SyntaxError | joiner-private-start!SyntaxError | nul-field!SyntaxError | same-line-elements!SyntaxError",
            "static-constructor=5 | escaped-field=1 | escaped-private=2 | escaped-member=4 | joiner-continues=6 | asi-elements=3 | async-newline-field=true,7",
        ]
    );
}
