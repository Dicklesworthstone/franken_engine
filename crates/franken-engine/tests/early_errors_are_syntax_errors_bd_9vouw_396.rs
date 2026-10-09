//! bd-9vouw.396: spec early errors the parser used to refuse as
//! UnsupportedSyntax are catchable SyntaxErrors through Function(), and
//! their valid look-alikes still run. Expected lines are Node v22.2.0's
//! output for the same source.

use frankenengine_engine::HybridRouter;

#[test]
fn early_errors_are_catchable_syntax_errors() {
    let source = r#"
var out = [];
function t(name, src) {
  try { Function(src); out.push(name + ":ok"); } catch (e) { out.push(name + "!" + e.name); }
}
t("rest-not-last", "var [...a, b] = [];");
t("two-rests", "var [...a, ...b] = [];");
t("object-rest-not-last", "var {...a, b} = {};");
t("assign-rest-not-last", "[...a, b] = [];");
t("bare-import", "import;");
t("import-no-args", "import();");
t("import-three-args", "import('a', {}, 1);");
t("new-import", "new import('a');");
t("delete-private", "class C { #x; m() { delete this.#x; } }");
t("field-arguments", "class C { x = arguments; }");
t("static-block-arguments", "class C { static { arguments; } }");
t("yield-label", "function* g() { yield: ; }");
t("await-label", "async function f() { await: ; }");
t("super-call", "function f() { super(); }");
t("yield-strict", "'use strict'; var x = yield;");
t("await-no-operand", "async function f() { await; }");
t("duplicate-private", "class C { #x; #x; }");
t("private-constructor", "class C { #constructor() {} }");
t("for-of-initializer", "for (var x = 0 of []) ;");
t("for-in-let-initializer", "for (let x = 0 in {}) ;");
t("optional-chain-target", "a?.b = 1;");
t("super-private", "class C extends Object { #x; m() { super.#x; } }");
t("strict-delete-name", "'use strict'; delete x;");
t("accessor-pattern", "({ get a() {} } = {});");
t("private-outside-member", "class C { #x; m() { return #x; } }");
t("private-name-space", "class C { #x; m() { return this.# x; } }");
t("typeof-yield", "function* g() { typeof yield; }");
t("anonymous-function-statement", "function () {}");
t("catch-empty-parameter", "try {} catch () {}");
t("try-alone", "try {}");
t("regexp-group", "/(?I:a)/;");
t("regexp-property", "/\\p{InAdlam}/u;");
t("regexp-flags", "/a/gg;");
console.log(out.join(" | "));
var ok = [];
function v(name, src, arg) {
  try { ok.push(name + "=" + Function("x", src)(arg)); } catch (e) { ok.push(name + "!" + e.name); }
}
v("rest-last", "var [a, ...b] = x; return a + ':' + b.join(',');", [1, 2, 3]);
v("object-rest-last", "var {a, ...b} = x; return a + ':' + Object.keys(b).join(',');", { a: 1, b: 2, c: 3 });
v("import-meta-free", "return typeof x;", 0);
v("yield-sloppy-name", "var yield = 4; return yield + x;", 1);
v("private-in", "class C { #x = 1; static has(o) { return #x in o; } } return C.has(new C()) + ',' + C.has(x);", {});
v("regexp-valid", "return /(?:a)\\p{Lu}/u.test(x);", "aB");
v("for-in-var-initializer", "var n = 0; for (var k = 0 in x) n++; return n;", { p: 1 });
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
            "rest-not-last!SyntaxError | two-rests!SyntaxError | object-rest-not-last!SyntaxError | assign-rest-not-last!SyntaxError | bare-import!SyntaxError | import-no-args!SyntaxError | import-three-args!SyntaxError | new-import!SyntaxError | delete-private!SyntaxError | field-arguments!SyntaxError | static-block-arguments!SyntaxError | yield-label!SyntaxError | await-label!SyntaxError | super-call!SyntaxError | yield-strict!SyntaxError | await-no-operand!SyntaxError | duplicate-private!SyntaxError | private-constructor!SyntaxError | for-of-initializer!SyntaxError | for-in-let-initializer!SyntaxError | optional-chain-target!SyntaxError | super-private!SyntaxError | strict-delete-name!SyntaxError | accessor-pattern!SyntaxError | private-outside-member!SyntaxError | private-name-space!SyntaxError | typeof-yield!SyntaxError | anonymous-function-statement!SyntaxError | catch-empty-parameter!SyntaxError | try-alone!SyntaxError | regexp-group!SyntaxError | regexp-property!SyntaxError | regexp-flags!SyntaxError",
            "rest-last=1:2,3 | object-rest-last=1:b,c | import-meta-free=number | yield-sloppy-name=5 | private-in=true,false | regexp-valid=true | for-in-var-initializer=1",
        ]
    );
}
