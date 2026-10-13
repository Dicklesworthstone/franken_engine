//! bd-9vouw.322: script source has the HTML-like comments of ES2020 Annex
//! B.1.3 (`<!--` anywhere, `-->` at the start of a line, after white space
//! and single-line block comments or a block comment holding a line
//! break), and the Function constructor parses its parameters as their
//! own production and its source text as exactly one declaration
//! (CreateDynamicFunction, ES2020 19.2.1.1.1), with the specified
//! `anonymous(P\n) {` text. Every `<!--` or `-->` comment in a script was
//! a parse error; a body that closed the function early
//! (`}; r.push('injected'); function y() {`) and parameters that closed
//! the list or opened a comment the body finished were accepted. A `-->`
//! after code on its line stays `--` then `>`. The lines are Node
//! v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn html_comments_and_function_constructor_productions_match_node() {
    let source = r#"
var c = 0;
<!-- c += 100
c += 1;
--> c += 100
c += 1;
   /* a */ /* b */ --> c += 100
c += 1; <!-- c += 100
var x = -1 <!--x;
0/*
*/--> c += 100
var w = 1; var q = w --> 0;
console.log(c, x, w, q);
var r = [];
function t(name, params, body) { try { var f = Function.apply(null, params.concat([body])); r.push(name + ":" + f.length + ":" + f(4)); } catch (e) { r.push(name + "!" + e.constructor.name); } }
t("close-body", [], "\n-->\nreturn 7");
t("close-body-no-lt", [], "-->\nreturn 8");
t("open-body", [], "<!--\nreturn 9");
t("close-params", ["\n-->"], "return 10");
t("open-params", ["a <!--"], "return a");
t("close-params-no-lt", ["-->"], "");
t("body-closes-early", [], "}; r.push('injected'); function y() {");
t("params-close-early", ["a) { return 1 }; (function (b"], "");
t("params-comment-spliced", ["a){ /*"], "*/ return 1");
t("plain", ["a", "b"], "return a * 2");
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
            "3 -1 0 true",
            "close-body:0:7 | close-body-no-lt:0:8 | open-body:0:9 | close-params:0:10 | open-params:1:4 | close-params-no-lt!SyntaxError | body-closes-early!SyntaxError | params-close-early!SyntaxError | params-comment-spliced!SyntaxError | plain:2:8",
        ]
    );
}
